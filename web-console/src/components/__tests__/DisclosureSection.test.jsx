import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import DisclosureSection from "../DisclosureSection";

describe("DisclosureSection", () => {
  test("toggles visibility with animated collapse state", async () => {
    const user = userEvent.setup();

    render(
      <DisclosureSection title="Technical appendix" subtitle="Deep analysis">
        <div>Nested content</div>
      </DisclosureSection>,
    );

    const toggle = screen.getByRole("button", { name: /technical appendix/i });
    const panel = document.getElementById(toggle.getAttribute("aria-controls"));
    const content = screen.getByText("Nested content");

    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(panel).toHaveAttribute("aria-hidden", "true");
    expect(panel).toHaveClass("animated-collapse", "is-closed");
    expect(content).toBeInTheDocument();

    await user.click(toggle);

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(panel).toHaveAttribute("aria-hidden", "false");
    expect(panel).toHaveClass("animated-collapse", "is-open");
    expect(content).toBeInTheDocument();

    await user.click(toggle);

    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(panel).toHaveAttribute("aria-hidden", "true");
    expect(panel).toHaveClass("animated-collapse", "is-closed");
    expect(content).toBeInTheDocument();
  });
});
