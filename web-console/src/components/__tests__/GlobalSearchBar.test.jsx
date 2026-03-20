import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import { I18nProvider } from "../../i18n";
import GlobalSearchBar from "../GlobalSearchBar";

function renderWithI18n(node) {
  return render(<I18nProvider>{node}</I18nProvider>);
}

describe("GlobalSearchBar", () => {
  test("debounces queries and opens a result", async () => {
    const onSearch = vi.fn().mockResolvedValue(undefined);
    const onSelectResult = vi.fn().mockResolvedValue(undefined);
    const onClear = vi.fn();
    const user = userEvent.setup();

    renderWithI18n(
      <GlobalSearchBar
        results={{
          query: "portal",
          total: 1,
          groups: { report: 1 },
          items: [
            {
              kind: "report",
              route: "reports",
              title: "Portal report",
              subtitle: "job-portal / completed",
              summary: "Portal review with login focus.",
              job_id: "job-portal",
            },
          ],
        }}
        searching={false}
        onSearch={onSearch}
        onSelectResult={onSelectResult}
        onClear={onClear}
      />,
    );

    await user.type(screen.getByRole("searchbox"), "po");

    await waitFor(() => expect(onSearch).toHaveBeenCalledWith("po"), { timeout: 1500 });
    await user.click(screen.getByRole("button", { name: /Portal report/i }));

    await waitFor(() => expect(onSelectResult).toHaveBeenCalledWith(expect.objectContaining({ title: "Portal report" })));
    expect(onClear).toHaveBeenCalled();
  });
});
