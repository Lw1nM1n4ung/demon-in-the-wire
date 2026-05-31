# /goal prompt — PDF Report + Branding Profiles

Copy the block below and use with `/goal` at the start of a session:

---

```
Add PDF report format and multi-profile report branding to Wire_Ghost on the rewrite-v2 branch. Reference CLAUDE.md and README.md for architecture — they are source of truth.

**FEATURE 1: PDF Report Format**

Add PDF as a first-class report format alongside DOCX, XLSX, HTML, and Dashboard. The PDF report should contain the same content and structure as the DOCX/HTML reports — same data, same ScanReport input, same branding from ReportConfig.

What to build:

1. Create `src/wireghost/reports/pdf_renderer.py` — a PDF renderer class with the same interface as DocxRenderer/HtmlRenderer (must have a `render(report, config, reports_dir) -> Path` method returning the created file path). Use weasyprint (HTML→PDF) as the rendering approach — it gives pixel-perfect parity with the HTML report and full CSS control. Alternative: reportlab for native PDF, but weasyprint is simpler and guarantees content parity.

2. The PDF must include all sections from the DOCX report:
   - Cover page (title, company name, logo, date, target, classification)
   - Executive summary with risk assessment
   - Statistics table (hosts, ports, findings count, severity breakdown)
   - Vulnerability breakdown by source
   - Detailed findings grouped by severity (CRITICAL→HIGH→MEDIUM→LOW→INFO), each with: title, severity badge (color-coded), host, endpoint, port, description, CVE/CWE/CVSS, evidence
   - Recommendations section
   - Footer with page numbers and branding

3. Register "pdf" in the `_DISPATCH` dict in `src/wireghost/reports/engine.py`:
   ```python
   "pdf": ("wireghost.reports.pdf_renderer", "PdfRenderer"),
   ```

4. Update `ScanConfig` and the `Scan` model's `report_formats` choices to include "pdf". Update the frontend scan creation form and the "Report Builder → Default Formats" selector. Update `ReportConfig.default_formats` default to include pdf.

5. The renderer must handle logo embedding (base64 inline in the HTML before PDF conversion), respect `brand_color` for headings/badges, and honor the section visibility flags (`include_cover`, `include_executive_summary`, etc.).

6. PDF-specific considerations:
   - Page size: A4
   - Page breaks between major sections (cover, summary, findings, recommendations)
   - Running header with report title
   - Running footer with page X of Y
   - Color severity badges rendered as filled rectangles (not CSS-dependent)
   - Hyperlinks in references should be clickable

**FEATURE 2: Report Branding Profiles**

Transform ReportConfig from a singleton into a multi-profile system. Users can create, name, and switch between branding profiles for different clients or engagement types.

What to build:

1. **Database migration** — Rename `ReportConfig` to `ReportProfile` (or keep ReportConfig and add profiles as a new model, with ReportConfig becoming the "active profile" pointer). The migration must:
   - Create the new model with all existing ReportConfig fields plus: `name` (CharField, required, unique per install), `is_default` (BooleanField, exactly one per install), `created_at`, `updated_at`
   - Migrate existing singleton row data into a default profile named "Default"
   - Drop the singleton UUID constraint — each profile gets a UUIDv7 PK
   - Remove the hardcoded `REPORT_CONFIG_UUID` singleton pattern from the model's `save()` — profiles are normal rows now
   - Add `active_profile` ForeignKey to SiteConfig (or use `is_default` flag)  
   - Migration number: follow the next available (0038 or higher)

2. **API changes** — Replace the single `GET/PUT /api/report-config/` function-based view with a `ReportProfileViewSet`:
   - `GET /api/report-profiles/` — list all profiles (Engineer+)
   - `POST /api/report-profiles/` — create profile (Engineer+, `report:config:write`)
   - `GET /api/report-profiles/<id>/` — detail
   - `PUT/PATCH /api/report-profiles/<id>/` — update
   - `DELETE /api/report-profiles/<id>/` — delete (prevent deleting the last remaining profile or the default)
   - `POST /api/report-profiles/<id>/set-default/` — set as default
   - `POST /api/report-profiles/<id>/logo/` — logo upload per profile (move from global endpoint)
   - Permission: `report:config:write` for write actions, `report:config:read` for list/retrieve (add this permission code if missing)

3. **Serializer** — `ReportProfileSerializer` excluding `id` on list, full on detail. Validate:
   - `brand_color` is a valid hex color (`#[0-9a-fA-F]{6}`)
   - `name` is unique across profiles
   - Prevent deleting the last profile

4. **Report generation integration** — Update `ReportEngine.generate()` to accept an optional `profile_id` parameter. The Celery task and the CLI `wireghost report` command should use the default profile unless a specific one is requested. Update `POST /api/scans/<id>/regenerate_reports/` to accept `profile_id` in the request body.

5. **Frontend** — Update `web/js/app/pages/report-builder.js`:
   - Profile selector dropdown (top of the page, shows all profiles, switches on selection)
   - "New Profile" / "Duplicate Profile" / "Delete Profile" buttons
   - Current profile name shown in the page header
   - When switching profiles, the form fields update without page reload
   - Logo upload is per-profile (upload button inside each profile context)
   - Default profile has a star/badge indicator
   - On scan creation page (`new-scan.js`), add optional profile selector if multiple profiles exist

6. **Backward compatibility** — The existing `ReportConfig.get()` call is used in the views, tasks, and possibly CLI. Create a shim:
   ```python
   class ReportConfig:
       @classmethod
       def get(cls):
           return ReportProfile.objects.get(is_default=True)
   ```
   This lets existing code work unchanged while new code uses ReportProfile directly.

**Shared constraints (both features):**
- Follow existing patterns: UUIDv7 PKs, DRF ViewSets with HasMethodPerm, vanilla JS page modules referencing WG.* helpers, ruff lint rules
- Add tests: pytest for PDF renderer (verify output is valid PDF, sections present), Django tests for ReportProfile CRUD and permission enforcement, frontend JS tests for profile switching logic
- Update `SCRIPTS_TO_RUN` in CLAUDE.md if CLI commands change
- No comments unless WHY is non-obvious
- Security: logo upload path traversal protection (Path.is_relative_to()), file extension whitelist (png/jpg/svg)
- The PDF renderer must not introduce new pip dependency conflicts — pin weasyprint version in both pyproject.toml and web_portal/requirements.txt
```

---

## Usage

```bash
/goal <paste the block above>
```

## Notes

- Prompt length: ~1,100 words — comprehensive enough for a multi-session feature
- All class names, file paths, and method signatures reference the actual codebase structure
- The prompt encodes architecture decisions (weasyprint over reportlab, ViewSet over function view, shim for backward compat) so you don't waste time debating approach
