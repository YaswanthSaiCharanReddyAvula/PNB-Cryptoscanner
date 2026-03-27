# Design System Specification: The Sentinel Intelligence Language

## 1. Overview & Creative North Star
### The Creative North Star: "The Architectural Dossier"
This design system rejects the "SaaS-template" look in favor of a high-density, editorial approach to security data. It treats the dashboard not as a collection of widgets, but as a sophisticated intelligence dossier. We achieve this through **Architectural Layering**: moving away from lines and borders toward a world of shifting tonal planes. The interface should feel authoritative, quiet, and impossibly sharp—mimicking the precision of quantum encryption.

By utilizing high-contrast typography scales and intentional asymmetry in layout, we guide the security analyst's eye to what matters most without the visual "noise" of traditional grid lines.

---

## 2. Colors & Surface Philosophy
The palette is rooted in `primary` (#000000) and `primary_container` (#131B2E), creating a deep, "Command Center" foundation.

### The "No-Line" Rule
**Strict Mandate:** Designers are prohibited from using 1px solid borders to define sections. Layout separation must be achieved exclusively through background color shifts.
*   **The Technique:** A `surface_container_low` (#F2F4F6) card sitting on a `surface` (#F7F9FB) background provides enough contrast for the human eye to perceive a boundary without the "clutter" of a stroke.

### Surface Hierarchy & Nesting
Treat the UI as physical layers of fine paper or frosted glass. Use the `surface_container` tiers to denote depth:
1.  **Base Layer:** `surface` (#F7F9FB)
2.  **Sectioning:** `surface_container` (#ECEEF0)
3.  **Interactive Elements:** `surface_container_highest` (#E0E3E5)
4.  **Floating Floating Content:** `surface_container_lowest` (#FFFFFF)

### The Glass & Gradient Rule
To provide "visual soul" to high-density data:
*   **KPI Cards:** Apply a subtle linear gradient from `primary` (#000000) to `primary_container` (#131B2E) at a 145-degree angle.
*   **Overlays:** Use `surface_container_lowest` with a 80% opacity and a `20px` backdrop-blur to create a "Quantum Glass" effect for modals and dropdowns.

---

## 3. Typography: Editorial Authority
We utilize a dual-font strategy to balance readability with a premium, bespoke feel.

*   **Display & Headlines (Manrope):** Used for "The Big Picture." High-impact, wide tracking (-0.02em), and bold weights to establish an institutional tone.
    *   *Display-LG:* 3.5rem (Use for high-level security scores).
*   **UI & Data (Inter):** Used for the "Working Surface." Inter is chosen for its exceptional legibility in high-density tables and status chips.
    *   *Title-SM (1rem):* Bold, for card titles.
    *   *Label-SM (0.6875rem):* All-caps with +0.05em tracking for metadata and table headers.

---

## 4. Elevation & Depth: Tonal Layering
Traditional drop shadows are largely replaced by **Tonal Layering**.

*   **The Layering Principle:** Place a `surface_container_lowest` card on a `surface_container_low` background. This "Soft Lift" is the signature of the system.
*   **Ambient Shadows:** For floating elements (Modals/Popovers), use a shadow with a blur radius of `24px`, spread of `-4px`, and an opacity of `6%` using the `on_surface` color.
*   **The Ghost Border Fallback:** If a border is required for accessibility in data tables, use `outline_variant` (#C6C6CD) at **15% opacity**. Never use 100% opaque borders.

---

## 5. Components & Interface Primitives

### Buttons
*   **Primary:** Solid `primary` (#000000) with `on_primary` text. Radius: `md` (0.375rem).
*   **Secondary:** `secondary_container` (#D5E3FD) with `on_secondary_container` (#57657B). No border.
*   **Tertiary/Ghost:** No background. `on_surface_variant` text. High-contrast hover state using `surface_container_high`.

### Status Chips (The Quantum Badge)
Standard Shadcn-style badges are elevated with a "Glow" state:
*   **CRITICAL:** Background: `error_container` (#FFDAD6), Text: `on_error_container` (#93000A).
*   **QUANTUM_SAFE:** Background: `emerald-100`, Text: `emerald-900` (Use a subtle 5% inner-glow to signify "Active Protection").

### Data Tables & Lists
*   **Rule:** Forbid divider lines. 
*   **Execution:** Use `spacing.3` (0.6rem) of vertical white space between rows. On hover, change the row background to `surface_container_low`. 
*   **Density:** Use `label-sm` for headers to allow more columns without visual crowding.

### Advanced Security Components
*   **The Risk Matrix:** A layered 2D grid using shifting opacities of `error` and `tertiary` to map threat vectors.
*   **The Pulse Indicator:** A small, animated radial gradient (2px) next to "Quantum Safe" statuses to indicate real-time monitoring.

---

## 6. Do's and Don'ts

### Do
*   **DO** use whitespace as a structural element. If a section feels crowded, increase the `spacing` scale rather than adding a line.
*   **DO** use `manrope` for any text larger than 1.5rem to maintain the premium editorial feel.
*   **DO** nest containers. A `surface_container_highest` element inside a `surface_container_low` element creates a sophisticated hierarchy.

### Don't
*   **DON'T** use pure black (#000000) for body text. Use `on_surface_variant` (#45464D) for long-form reading to reduce eye strain.
*   **DON'T** use standard 4px shadows. Our shadows must be "ambient"—large, soft, and nearly invisible.
*   **DON'T** use 100% opaque lines to separate table data. If separation is needed, use a `1px` gap that reveals the `surface_container` color underneath.