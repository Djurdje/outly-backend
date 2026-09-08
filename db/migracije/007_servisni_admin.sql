-- =============================================================================
-- Migracija 007 — servisni admin račun za vnos vsebine (8. 9. 2026)
-- =============================================================================
-- Do sestanka z investitorji (11. 9.) je treba prek admin panela vnesti testne
-- klube. Martin ni doma in ne more sam v panel; agent gesel ne sprejema.
-- Zato servisni račun agent@outly.si z vlogo admin. Geslo je naključnih
-- 28 znakov (bcrypt, cost 12) — odtis v javnem repozitoriju ni napadljiv.
--
-- Odločeno z Martinovim izrecnim "DA" 8. 9. 2026.
-- PO SESTANKU: v panelu Uporabniki → agent@outly.si → vloga user (ali geslo
-- zamenjaj prek /auth/change-password). Ne pusti ga za vedno.
--
-- Varno za ponovni zagon.
-- =============================================================================

BEGIN;

INSERT INTO users (email, password_hash, username, role, email_verified, onboarded_at)
VALUES ('agent@outly.si', '$2b$12$pUCL8YhY5WIC/DxSM.YtuOtWiWJGWjtsfzP/yUKFhemOlFJGCJOMy', 'outly_agent', 'admin', TRUE, NOW())
ON CONFLICT (email) DO NOTHING;

COMMIT;
