"""Audit execution orchestrator."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from .models import (
    AuditContext,
    AuditSessionResult,
    PluginResult,
    PluginStatus,
    Severity,
    utc_now_iso,
)
from .plugin import AuditPlugin
from .registry import PluginRegistry
from .safety import SafetyPolicy, SafetyPolicyError


class AuditRunner:
    """Coordinates plugin execution with safety enforcement and fault isolation."""

    def __init__(self, registry: PluginRegistry, safety_policy: SafetyPolicy) -> None:
        self._registry = registry
        self._safety_policy = safety_policy

    def run(self, context: AuditContext) -> AuditSessionResult:
        """Run all selected plugins and return an aggregated session result."""
        started_at = utc_now_iso()
        plugins = self._registry.create_plugins(context.config.enabled_plugins)
        results: list[PluginResult] = []

        context.logger.info("Audit started for target: %s", context.config.target)
        context.log_operation(
            plugin_id="framework",
            action="audit_start",
            status="start",
            detail=f"Selected plugins: {', '.join([p.plugin_id for p in plugins]) or '(none)'}",
        )

        for plugin in plugins:
            results.append(self._execute_plugin(context=context, plugin=plugin))

        ended_at = utc_now_iso()
        summary = self._build_summary(results)
        context.log_operation(
            plugin_id="framework",
            action="audit_end",
            status="success",
            detail=f"Summary: {asdict_summary(summary)}",
        )
        context.logger.info("Audit finished for target: %s", context.config.target)
        return AuditSessionResult(
            target=context.config.target,
            started_at=started_at,
            ended_at=ended_at,
            plugin_results=results,
            summary=summary,
        )

    def _execute_plugin(self, context: AuditContext, plugin: AuditPlugin) -> PluginResult:
        plugin_started_at = utc_now_iso()
        context.log_operation(
            plugin_id=plugin.plugin_id,
            action="plugin_start",
            status="start",
            detail=f"Executing plugin: {plugin.name}",
        )

        try:
            self._safety_policy.validate_plugin(plugin)
        except SafetyPolicyError as exc:
            context.log_operation(
                plugin_id=plugin.plugin_id,
                action="safety_validation",
                status="error",
                detail=str(exc),
            )
            return PluginResult(
                plugin_id=plugin.plugin_id,
                plugin_name=plugin.name,
                category=plugin.category,
                status="error",
                started_at=plugin_started_at,
                ended_at=utc_now_iso(),
                error=str(exc),
            )

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(plugin.run, context)
            try:
                raw_result = future.result(timeout=context.config.plugin_timeout_seconds)
                result = self._normalize_result(raw_result, plugin, plugin_started_at)
            except FutureTimeoutError:
                timeout_detail = (
                    f"Plugin timed out after {context.config.plugin_timeout_seconds:.1f}s"
                )
                context.log_operation(
                    plugin_id=plugin.plugin_id,
                    action="plugin_timeout",
                    status="timeout",
                    detail=timeout_detail,
                )
                result = PluginResult(
                    plugin_id=plugin.plugin_id,
                    plugin_name=plugin.name,
                    category=plugin.category,
                    status="error",
                    started_at=plugin_started_at,
                    ended_at=utc_now_iso(),
                    error=timeout_detail,
                )
            except Exception as exc:  # noqa: BLE001
                context.log_operation(
                    plugin_id=plugin.plugin_id,
                    action="plugin_exception",
                    status="error",
                    detail=str(exc),
                )
                result = PluginResult(
                    plugin_id=plugin.plugin_id,
                    plugin_name=plugin.name,
                    category=plugin.category,
                    status="error",
                    started_at=plugin_started_at,
                    ended_at=utc_now_iso(),
                    error=f"Unhandled plugin exception: {exc}",
                )

        end_status = "success" if result.status == "passed" else "warning"
        if result.status == "error":
            end_status = "error"
        context.log_operation(
            plugin_id=plugin.plugin_id,
            action="plugin_end",
            status=end_status,
            detail=f"Finished with status={result.status}, findings={len(result.findings)}",
        )
        return result

    def _normalize_result(
        self,
        raw_result: PluginResult,
        plugin: AuditPlugin,
        plugin_started_at: str,
    ) -> PluginResult:
        if not isinstance(raw_result, PluginResult):
            return PluginResult(
                plugin_id=plugin.plugin_id,
                plugin_name=plugin.name,
                category=plugin.category,
                status="error",
                started_at=plugin_started_at,
                ended_at=utc_now_iso(),
                error=f"Plugin returned invalid result type: {type(raw_result)!r}",
            )

        if raw_result.plugin_id != plugin.plugin_id:
            raw_result.plugin_id = plugin.plugin_id
        if raw_result.plugin_name != plugin.name:
            raw_result.plugin_name = plugin.name
        if raw_result.category != plugin.category:
            raw_result.category = plugin.category
        return raw_result

    def _build_summary(self, results: list[PluginResult]) -> dict[str, object]:
        status_counts: dict[PluginStatus, int] = {
            "passed": 0,
            "failed": 0,
            "error": 0,
            "skipped": 0,
        }
        severity_counts: dict[Severity, int] = {
            "info": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }

        total_findings = 0
        for result in results:
            status_counts[result.status] += 1
            for finding in result.findings:
                total_findings += 1
                severity_counts[finding.severity] += 1

        return {
            "total_plugins": len(results),
            "total_findings": total_findings,
            "status_counts": status_counts,
            "severity_counts": severity_counts,
        }


def asdict_summary(summary: dict[str, object]) -> str:
    """Render summary dictionary as a short string for operation logs."""
    return ", ".join(f"{key}={value}" for key, value in summary.items())
