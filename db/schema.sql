-- =============================================================================
-- Outly — shema podatkovne baze (GENERIRANA, ne urejaj rocno)
-- =============================================================================
-- Vir resnice so migracije v db/migracije/ (poganja jih db/migrate.js ob vsakem
-- deployu). Ta datoteka je izvoz sheme (pg_dump --schema-only) iz baze, na
-- kateri so bile pognane vse migracije 000–041, in sluzi samo za branje:
-- da je struktura vidna na enem mestu in da se baze ne da izgubiti.
--
-- Osvezi po vsaki novi migraciji:
--   pg_dump --schema-only --no-owner --no-privileges "$DATABASE_URL" > db/schema.sql
-- (in ta glava nazaj na vrh). Prejsnja rocna rekonstrukcija je bila zastarela
-- (ni imela orders/tickets/refresh_tokens/...) — zato zdaj izvoz.
-- =============================================================================
--
-- PostgreSQL database dump
--

\restrict eWqM0o0zcTAGrdYkf9O2phn5BgBcJ95hBB7AuTtELkJWbdfiiTJ1tdPoLSjHnWQ

-- Dumped from database version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: rezerviraj_zalogo(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.rezerviraj_zalogo() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    zmogljivost INTEGER;
    zasedeno    INTEGER;
BEGIN
    -- VIP miza ima lastno zalogo (I13), navadne vstopnice je ne smejo porabiti ali zaklepati.
    IF NEW.table_id IS NOT NULL THEN
        RETURN NEW;
    END IF;
    -- Guest lista (035, I24): brezplacne vstopnice, dodeljene od admina; ne stejejo v kapaciteto in ne zaklepajo dogodka.
    IF NEW.guest_list_id IS NOT NULL THEN
        RETURN NEW;
    END IF;

    -- FOR UPDATE zaklene vrstico dogodka do konca transakcije.
    SELECT capacity, sold_count INTO zmogljivost, zasedeno
    FROM events WHERE id = NEW.event_id FOR UPDATE;

    IF zmogljivost IS NOT NULL AND zasedeno + NEW.quantity > zmogljivost THEN
        RAISE EXCEPTION 'Ni dovolj vstopnic: na voljo %, zahtevano %',
            zmogljivost - zasedeno, NEW.quantity
            USING ERRCODE = 'check_violation';
    END IF;

    UPDATE events SET sold_count = sold_count + NEW.quantity WHERE id = NEW.event_id;
    RETURN NEW;
END;
$$;


--
-- Name: sprosti_zalogo(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sprosti_zalogo() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.table_id IS NOT NULL OR OLD.guest_list_id IS NOT NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.status IN ('cancelled','refunded','failed')
       AND OLD.status NOT IN ('cancelled','refunded','failed') THEN
        UPDATE events SET sold_count = GREATEST(0, sold_count - OLD.quantity)
        WHERE id = OLD.event_id;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: starost(date); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.starost(rojstvo date) RETURNS integer
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT CASE WHEN rojstvo IS NULL THEN NULL
                ELSE EXTRACT(YEAR FROM AGE(CURRENT_DATE, rojstvo))::INTEGER END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: bottle_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bottle_packages (
    id integer NOT NULL,
    club_id integer NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    sort smallint DEFAULT 0 NOT NULL,
    archived_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT bottle_packages_desc_chk CHECK ((char_length(description) <= 200)),
    CONSTRAINT bottle_packages_name_chk CHECK (((char_length(name) >= 1) AND (char_length(name) <= 60)))
);


--
-- Name: bottle_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.bottle_packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: bottle_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.bottle_packages_id_seq OWNED BY public.bottle_packages.id;


--
-- Name: club_event_notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.club_event_notifications (
    id integer NOT NULL,
    user_id integer NOT NULL,
    event_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    seen_at timestamp with time zone
);


--
-- Name: club_event_notifications_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.club_event_notifications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: club_event_notifications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.club_event_notifications_id_seq OWNED BY public.club_event_notifications.id;


--
-- Name: club_follows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.club_follows (
    club_id integer NOT NULL,
    user_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: club_invites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.club_invites (
    id integer NOT NULL,
    club_id integer NOT NULL,
    user_id integer NOT NULL,
    role text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    invited_by_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    responded_at timestamp with time zone,
    CONSTRAINT club_invites_role_check CHECK ((role = ANY (ARRAY['manager'::text, 'doorman'::text, 'bartender'::text]))),
    CONSTRAINT club_invites_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'accepted'::text, 'declined'::text, 'cancelled'::text])))
);


--
-- Name: club_invites_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.club_invites_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: club_invites_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.club_invites_id_seq OWNED BY public.club_invites.id;


--
-- Name: club_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.club_members (
    id integer NOT NULL,
    club_id integer NOT NULL,
    user_id integer NOT NULL,
    role text NOT NULL,
    invited_by_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT club_members_role_check CHECK ((role = ANY (ARRAY['manager'::text, 'doorman'::text, 'bartender'::text])))
);


--
-- Name: club_members_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.club_members_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: club_members_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.club_members_id_seq OWNED BY public.club_members.id;


--
-- Name: club_tables; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.club_tables (
    id integer NOT NULL,
    club_id integer NOT NULL,
    label text NOT NULL,
    x smallint NOT NULL,
    y smallint NOT NULL,
    w smallint NOT NULL,
    h smallint NOT NULL,
    shape text DEFAULT 'round'::text NOT NULL,
    seats smallint NOT NULL,
    price_cents integer NOT NULL,
    archived_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    event_id integer,
    CONSTRAINT club_tables_label_chk CHECK (((char_length(label) >= 1) AND (char_length(label) <= 20))),
    CONSTRAINT club_tables_pos_chk CHECK (((x >= 0) AND (y >= 0) AND (w >= 1) AND (h >= 1))),
    CONSTRAINT club_tables_price_chk CHECK ((price_cents >= 0)),
    CONSTRAINT club_tables_seats_chk CHECK (((seats >= 1) AND (seats <= 20))),
    CONSTRAINT club_tables_shape_chk CHECK ((shape = ANY (ARRAY['round'::text, 'rect'::text])))
);


--
-- Name: COLUMN club_tables.event_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.club_tables.event_id IS 'NULL = miza kluba; sicer miza razporeda tega dogodka (039), club_id = events.club_id. event_tables (izjeme) veljajo samo za mize z event_id IS NULL.';


--
-- Name: club_tables_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.club_tables_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: club_tables_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.club_tables_id_seq OWNED BY public.club_tables.id;


--
-- Name: clubs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.clubs (
    id integer NOT NULL,
    owner_user_id integer NOT NULL,
    name text NOT NULL,
    logo_url text DEFAULT ''::text NOT NULL,
    banner_url text DEFAULT ''::text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    contact_email text DEFAULT ''::text NOT NULL,
    contact_phone text DEFAULT ''::text NOT NULL,
    instagram text DEFAULT ''::text NOT NULL,
    website text DEFAULT ''::text NOT NULL,
    address text DEFAULT ''::text NOT NULL,
    city text DEFAULT ''::text NOT NULL,
    country text DEFAULT ''::text NOT NULL,
    lat double precision,
    lng double precision,
    min_age smallint DEFAULT 18 NOT NULL,
    genres text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    stripe_account_id text,
    stripe_charges_enabled boolean DEFAULT false NOT NULL,
    stripe_payouts_enabled boolean DEFAULT false NOT NULL,
    stripe_onboarded_at timestamp with time zone,
    hidden boolean DEFAULT false NOT NULL,
    bar_prices jsonb DEFAULT '[]'::jsonb NOT NULL,
    gallery_urls text[] DEFAULT '{}'::text[] NOT NULL,
    video_url text DEFAULT ''::text NOT NULL,
    floor_plan jsonb,
    commission_bps integer,
    is_organizer boolean DEFAULT false NOT NULL,
    is_official boolean DEFAULT false NOT NULL,
    CONSTRAINT clubs_bar_prices_chk CHECK ((jsonb_typeof(bar_prices) = 'array'::text)),
    CONSTRAINT clubs_commission_bps_chk CHECK (((commission_bps IS NULL) OR ((commission_bps >= 0) AND (commission_bps <= 5000)))),
    CONSTRAINT clubs_coords_chk CHECK (((lat IS NULL) = (lng IS NULL))),
    CONSTRAINT clubs_gallery_chk CHECK ((cardinality(gallery_urls) <= 3)),
    CONSTRAINT clubs_lat_chk CHECK (((lat IS NULL) OR ((lat >= ('-90'::integer)::double precision) AND (lat <= (90)::double precision)))),
    CONSTRAINT clubs_lng_chk CHECK (((lng IS NULL) OR ((lng >= ('-180'::integer)::double precision) AND (lng <= (180)::double precision)))),
    CONSTRAINT clubs_min_age_chk CHECK (((min_age >= 0) AND (min_age <= 99))),
    CONSTRAINT clubs_name_chk CHECK ((length(TRIM(BOTH FROM name)) > 0))
);


--
-- Name: COLUMN clubs.commission_bps; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.clubs.commission_bps IS 'Provizija Outlyja za ta klub v baznih tockah (100 = 1 %). NULL = privzeta (PROVIZIJA_ODSTOTEK). Nastavi admin.';


--
-- Name: COLUMN clubs.is_organizer; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.clubs.is_organizer IS 'Organizator dogodkov brez lastnega prizorisca (037): isti profil kot klub, brez naslova in pina; vsak njegov dogodek ima prizorisce.';


--
-- Name: COLUMN clubs.is_official; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.clubs.is_official IS 'Uradni profil Outly (037): njegovi prihajajoci dogodki so v razdelku »Organized by Outly« na Home. Nastavi SAMO admin (admin panel).';


--
-- Name: clubs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.clubs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: clubs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.clubs_id_seq OWNED BY public.clubs.id;


--
-- Name: creator_applications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.creator_applications (
    id integer NOT NULL,
    user_id integer,
    business_name text NOT NULL,
    business_type text DEFAULT ''::text NOT NULL,
    business_address text DEFAULT ''::text NOT NULL,
    city text DEFAULT ''::text NOT NULL,
    licence_id text DEFAULT ''::text NOT NULL,
    contact_name text NOT NULL,
    contact_role text DEFAULT ''::text NOT NULL,
    email text NOT NULL,
    phone text DEFAULT ''::text NOT NULL,
    message text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'new'::text NOT NULL,
    decided_at timestamp with time zone,
    decided_by integer,
    decision_note text DEFAULT ''::text NOT NULL,
    club_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ca_business_name_chk CHECK (((length(TRIM(BOTH FROM business_name)) >= 2) AND (length(TRIM(BOTH FROM business_name)) <= 120))),
    CONSTRAINT ca_contact_name_chk CHECK (((length(TRIM(BOTH FROM contact_name)) >= 2) AND (length(TRIM(BOTH FROM contact_name)) <= 120))),
    CONSTRAINT ca_decided_chk CHECK (((status = 'new'::text) = (decided_at IS NULL))),
    CONSTRAINT ca_email_chk CHECK (((email ~* '^[^@[:space:]]+@[^@[:space:].]+\.[^@[:space:]]+$'::text) AND ((length(email) >= 5) AND (length(email) <= 254)))),
    CONSTRAINT ca_status_chk CHECK ((status = ANY (ARRAY['new'::text, 'approved'::text, 'rejected'::text])))
);


--
-- Name: creator_applications_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.creator_applications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: creator_applications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.creator_applications_id_seq OWNED BY public.creator_applications.id;


--
-- Name: device_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    token text NOT NULL,
    platform text DEFAULT 'ios'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    invalid_at timestamp with time zone,
    CONSTRAINT device_tokens_platform_chk CHECK ((platform = 'ios'::text)),
    CONSTRAINT device_tokens_token_dolzina_chk CHECK (((char_length(token) >= 64) AND (char_length(token) <= 200)))
);


--
-- Name: TABLE device_tokens; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.device_tokens IS 'Zetoni naprav za potisna obvestila APNs (040). Zeton je skrivnost naprave: nikoli v dnevniku, nikoli v odgovorih API-ja.';


--
-- Name: COLUMN device_tokens.invalid_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_tokens.invalid_at IS 'Nastavi backend ob odzivu APNs 410 / Unregistered ali 400 BadDeviceToken (DeviceTokenNotForTopic je napaka nastavitve topica in zetona NE oznaci). POST /me/devices ga postavi na NULL.';


--
-- Name: device_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.device_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: device_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.device_tokens_id_seq OWNED BY public.device_tokens.id;


--
-- Name: event_favorites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_favorites (
    user_id integer NOT NULL,
    event_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: event_interest; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_interest (
    user_id integer NOT NULL,
    event_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: event_tables; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_tables (
    event_id integer NOT NULL,
    table_id integer NOT NULL,
    price_cents integer,
    disabled boolean DEFAULT false NOT NULL,
    CONSTRAINT event_tables_price_chk CHECK (((price_cents IS NULL) OR (price_cents >= 0)))
);


--
-- Name: events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events (
    id integer NOT NULL,
    club_id integer NOT NULL,
    title text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    poster_url text DEFAULT ''::text NOT NULL,
    start_at timestamp with time zone NOT NULL,
    end_at timestamp with time zone,
    min_age smallint DEFAULT 18 NOT NULL,
    genres text[] DEFAULT '{}'::text[] NOT NULL,
    status text DEFAULT 'published'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    ticket_price_cents integer,
    currency character(3) DEFAULT 'EUR'::bpchar NOT NULL,
    ticket_url text DEFAULT ''::text NOT NULL,
    capacity integer,
    sold_count integer DEFAULT 0 NOT NULL,
    vat_rate numeric(4,3),
    sales_open_at timestamp with time zone,
    sales_close_at timestamp with time zone,
    recap_video_url text DEFAULT ''::text NOT NULL,
    vip_enabled boolean DEFAULT false NOT NULL,
    venue_club_id integer,
    venue_name text DEFAULT ''::text NOT NULL,
    venue_address text DEFAULT ''::text NOT NULL,
    venue_city text DEFAULT ''::text NOT NULL,
    venue_lat double precision,
    venue_lng double precision,
    vip_layout_source text DEFAULT 'club'::text NOT NULL,
    floor_plan jsonb,
    vip_layout_from_club_id integer,
    CONSTRAINT events_capacity_chk CHECK (((capacity IS NULL) OR (capacity > 0))),
    CONSTRAINT events_end_chk CHECK (((end_at IS NULL) OR (end_at > start_at))),
    CONSTRAINT events_floor_plan_chk CHECK (((floor_plan IS NULL) OR (jsonb_typeof(floor_plan) = 'object'::text))),
    CONSTRAINT events_min_age_chk CHECK (((min_age >= 0) AND (min_age <= 99))),
    CONSTRAINT events_price_chk CHECK (((ticket_price_cents IS NULL) OR (ticket_price_cents >= 0))),
    CONSTRAINT events_sales_window_chk CHECK (((sales_close_at IS NULL) OR (sales_open_at IS NULL) OR (sales_close_at > sales_open_at))),
    CONSTRAINT events_sold_chk CHECK (((sold_count >= 0) AND ((capacity IS NULL) OR (sold_count <= capacity)))),
    CONSTRAINT events_status_chk CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'cancelled'::text]))),
    CONSTRAINT events_title_chk CHECK ((length(TRIM(BOTH FROM title)) > 0)),
    CONSTRAINT events_vat_chk CHECK (((vat_rate IS NULL) OR ((vat_rate >= (0)::numeric) AND (vat_rate < (1)::numeric)))),
    CONSTRAINT events_venue_club_chk CHECK (((venue_club_id IS NULL) OR (venue_club_id <> club_id))),
    CONSTRAINT events_venue_coords_chk CHECK ((((venue_lat IS NULL) = (venue_lng IS NULL)) AND ((venue_lat IS NULL) OR (((venue_lat >= ('-90'::integer)::double precision) AND (venue_lat <= (90)::double precision)) AND ((venue_lng >= ('-180'::integer)::double precision) AND (venue_lng <= (180)::double precision)))))),
    CONSTRAINT events_vip_layout_source_chk CHECK ((vip_layout_source = ANY (ARRAY['club'::text, 'event'::text])))
);


--
-- Name: COLUMN events.venue_club_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.events.venue_club_id IS 'Gostiteljski klub z Outlyja (037). Dogodek je viden tudi na njegovi strani (hosted), skenira pa samo ekipa events.club_id. Ob izbrisu gostitelja NULL.';


--
-- Name: COLUMN events.venue_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.events.venue_name IS 'Prosto vpisano prizorisce (037); prazno, ce je venue_club_id podan.';


--
-- Name: COLUMN events.vip_layout_source; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.events.vip_layout_source IS 'Vir razporeda VIP miz (039): club = tloris kluba prodajalca, event = razpored dogodka (events.floor_plan + club_tables WHERE event_id = id).';


--
-- Name: COLUMN events.floor_plan; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.events.floor_plan IS 'Tloris razporeda dogodka (039), enaka oblika kot clubs.floor_plan. Pomemben samo pri vip_layout_source = event.';


--
-- Name: COLUMN events.vip_layout_from_club_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.events.vip_layout_from_club_id IS 'Klub, iz katerega je kopija razporeda (039; posnetek, poznejse spremembe kluba ne vplivajo). Samo informativno.';


--
-- Name: events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.events_id_seq OWNED BY public.events.id;


--
-- Name: friend_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.friend_requests (
    id integer NOT NULL,
    from_user_id integer NOT NULL,
    to_user_id integer NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    responded_at timestamp with time zone,
    CONSTRAINT friend_requests_not_self_chk CHECK ((from_user_id <> to_user_id)),
    CONSTRAINT friend_requests_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'accepted'::text, 'declined'::text, 'cancelled'::text])))
);


--
-- Name: friend_requests_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.friend_requests_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: friend_requests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.friend_requests_id_seq OWNED BY public.friend_requests.id;


--
-- Name: friendships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.friendships (
    user_a integer NOT NULL,
    user_b integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT friendships_order_chk CHECK ((user_a < user_b))
);


--
-- Name: gost_zetoni; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.gost_zetoni (
    token_hash text NOT NULL,
    order_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT gost_zetoni_hash_chk CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: TABLE gost_zetoni; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.gost_zetoni IS 'Zetoni za pogled gostujocega narocila (GET /guest/order). Samo sha256 zetona (hex, 64 znakov); velja do konca dogodka + 30 dni (preverja poizvedba, ne stolpec).';


--
-- Name: gost_zetoni_vstopnic; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.gost_zetoni_vstopnic (
    token_hash text NOT NULL,
    ticket_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT gost_zetoni_vstopnic_hash_chk CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: TABLE gost_zetoni_vstopnic; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.gost_zetoni_vstopnic IS 'Zetoni za pogled gostujoce vstopnice (GET /guest/ticket). Samo sha256 zetona (hex); velja do konca dogodka + 30 dni (preverja poizvedba).';


--
-- Name: guest_list_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.guest_list_members (
    id bigint NOT NULL,
    guest_list_id bigint NOT NULL,
    user_id integer,
    ticket_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    removed_at timestamp with time zone,
    seen_at timestamp with time zone
);


--
-- Name: TABLE guest_list_members; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.guest_list_members IS 'Povabljeni prijatelj na guest listi in njegova vstopnica. Odstranitev = removed_at in vstopnica void.';


--
-- Name: COLUMN guest_list_members.seen_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.guest_list_members.seen_at IS 'Povabljenec je obvestilo o vabilu videl (zvonec). NULL = neprebrano; vabila pred 036 so prebrana.';


--
-- Name: guest_list_members_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.guest_list_members_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: guest_list_members_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.guest_list_members_id_seq OWNED BY public.guest_list_members.id;


--
-- Name: guest_lists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.guest_lists (
    id bigint NOT NULL,
    event_id integer NOT NULL,
    host_user_id integer,
    spots smallint NOT NULL,
    note text DEFAULT ''::text NOT NULL,
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT guest_lists_note_chk CHECK ((char_length(note) <= 200)),
    CONSTRAINT guest_lists_spots_chk CHECK (((spots >= 0) AND (spots <= 20)))
);


--
-- Name: TABLE guest_lists; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.guest_lists IS 'Guest lista: admin da gostitelju stevilo mest na enem dogodku; gostitelj povabi prijatelje (brez placila). Preklic = revoked_at (vrstica ostane).';


--
-- Name: guest_lists_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.guest_lists_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: guest_lists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.guest_lists_id_seq OWNED BY public.guest_lists.id;


--
-- Name: omejitve; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.omejitve (
    kljuc text NOT NULL,
    okno_do timestamp with time zone NOT NULL,
    stevec integer NOT NULL,
    CONSTRAINT omejitve_stevec_check CHECK ((stevec >= 0))
)
WITH (fillfactor='70');


--
-- Name: TABLE omejitve; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.omejitve IS 'Omejevalnik poskusov (issue #24): kljuc = HMAC(pot:meja:okno:IP), stevec poskusov v oknu. Kratkotrajno, UNLOGGED, ni v izvozu baze.';


--
-- Name: orders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.orders (
    id bigint NOT NULL,
    public_ref text NOT NULL,
    user_id integer,
    event_id integer NOT NULL,
    club_id integer NOT NULL,
    quantity smallint NOT NULL,
    unit_price_cents integer NOT NULL,
    total_cents integer NOT NULL,
    currency character(3) DEFAULT 'EUR'::bpchar NOT NULL,
    application_fee_cents integer DEFAULT 0 NOT NULL,
    vat_rate numeric(4,3),
    status text DEFAULT 'pending'::text NOT NULL,
    stripe_payment_intent_id text,
    stripe_charge_id text,
    stripe_account_id text,
    buyer_email text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    paid_at timestamp with time zone,
    cancelled_at timestamp with time zone,
    refunded_cents integer DEFAULT 0 NOT NULL,
    table_id integer,
    table_label text,
    table_seats smallint,
    package_id integer,
    package_name text,
    package_description text,
    idempotency_key uuid,
    stripe_checkout_session_id text,
    checkout_url text,
    checkout_expires_at timestamp with time zone,
    guest_email text,
    guest_terms_version text,
    guest_terms_accepted_at timestamp with time zone,
    guest_age_min smallint,
    guest_mail_sent_at timestamp with time zone,
    guest_mail_claimed_at timestamp with time zone,
    guest_mail_attempts smallint DEFAULT 0 NOT NULL,
    guest_list_id bigint,
    CONSTRAINT orders_fee_chk CHECK (((application_fee_cents >= 0) AND (application_fee_cents <= total_cents))),
    CONSTRAINT orders_guest_chk CHECK (((guest_email IS NULL) OR ((guest_email = lower(guest_email)) AND (char_length(guest_email) <= 254) AND (POSITION(('@'::text) IN (guest_email)) > 1) AND (table_id IS NULL) AND (guest_terms_version IS NOT NULL) AND (guest_terms_accepted_at IS NOT NULL)))),
    CONSTRAINT orders_guest_lista_chk CHECK (((guest_list_id IS NULL) OR ((status = 'paid'::text) AND (quantity = 1) AND (unit_price_cents = 0) AND (total_cents = 0) AND (application_fee_cents = 0) AND (refunded_cents = 0) AND (table_id IS NULL) AND (package_id IS NULL) AND (guest_email IS NULL) AND (stripe_payment_intent_id IS NULL) AND (stripe_charge_id IS NULL) AND (stripe_checkout_session_id IS NULL) AND (stripe_account_id IS NULL)))),
    CONSTRAINT orders_paid_chk CHECK (((status <> 'paid'::text) OR (paid_at IS NOT NULL))),
    CONSTRAINT orders_price_chk CHECK (((unit_price_cents >= 0) AND (total_cents >= 0))),
    CONSTRAINT orders_qty_chk CHECK (((quantity > 0) AND (quantity <= 20))),
    CONSTRAINT orders_refund_chk CHECK (((refunded_cents >= 0) AND (refunded_cents <= total_cents))),
    CONSTRAINT orders_status_chk CHECK ((status = ANY (ARRAY['pending'::text, 'paid'::text, 'failed'::text, 'cancelled'::text, 'refunded'::text, 'partially_refunded'::text]))),
    CONSTRAINT orders_table_chk CHECK (((table_id IS NULL) OR ((quantity = 1) AND (table_label IS NOT NULL) AND ((table_seats >= 1) AND (table_seats <= 20))))),
    CONSTRAINT orders_total_chk CHECK ((total_cents = (unit_price_cents * quantity)))
);


--
-- Name: COLUMN orders.idempotency_key; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders.idempotency_key IS 'Glava Idempotency-Key ob nakupu (UUID, issue #112, I18). NULL = nakup brez kljuca. Unikaten po (user_id, idempotency_key).';


--
-- Name: COLUMN orders.stripe_checkout_session_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders.stripe_checkout_session_id IS 'Stripe Checkout seja (cs_...), issue #19. NULL pri testnih narocilih.';


--
-- Name: COLUMN orders.checkout_url; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders.checkout_url IS 'URL Stripove placilne strani za cakajoce narocilo (ponovitev z Idempotency-Key vrne istega).';


--
-- Name: COLUMN orders.checkout_expires_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders.checkout_expires_at IS 'Potek Checkout seje; pospravljalec po njem narocilo preveri pri Stripu in preklice.';


--
-- Name: COLUMN orders.guest_email; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders.guest_email IS 'E-naslov gosta, ki je kupil brez racuna (user_id NULL do prevzema). Osebni podatek kot buyer_email; ob izbrisu racuna se postavi na NULL.';


--
-- Name: COLUMN orders.guest_list_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders.guest_list_id IS 'Narocilo guest liste (035, I24): total 0, status paid, brez Stripa. NI prodaja: izlocitev iz sold_count, tickets_sold, bruto, stevila narocil.';


--
-- Name: orders_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.orders_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: orders_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.orders_id_seq OWNED BY public.orders.id;


--
-- Name: reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reports (
    id integer NOT NULL,
    reporter_id integer,
    target_type text NOT NULL,
    target_id integer NOT NULL,
    reason text NOT NULL,
    details text,
    status text DEFAULT 'open'::text NOT NULL,
    note text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by integer,
    CONSTRAINT reports_details_chk CHECK (((details IS NULL) OR (char_length(details) <= 1000))),
    CONSTRAINT reports_note_chk CHECK (((note IS NULL) OR (char_length(note) <= 1000))),
    CONSTRAINT reports_reason_chk CHECK ((reason = ANY (ARRAY['spam'::text, 'harassment'::text, 'inappropriate'::text, 'impersonation'::text, 'illegal'::text, 'other'::text]))),
    CONSTRAINT reports_resolved_chk CHECK (((status = 'resolved'::text) = (resolved_at IS NOT NULL))),
    CONSTRAINT reports_status_chk CHECK ((status = ANY (ARRAY['open'::text, 'resolved'::text]))),
    CONSTRAINT reports_target_type_chk CHECK ((target_type = ANY (ARRAY['user'::text, 'club'::text, 'event'::text, 'media'::text])))
);


--
-- Name: TABLE reports; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.reports IS 'Prijave zlorabe (041): uporabnik, klub, dogodek ali slika kluba (media: target_id = id kluba). Brez tujega kljuca na cilj. reporter_id SET NULL ob izbrisu racuna.';


--
-- Name: COLUMN reports.target_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.reports.target_id IS 'Id cilja glede na target_type (users.id | clubs.id | events.id | clubs.id za media). Polimorfen, brez FK: prijava ostane kot dokaz.';


--
-- Name: reports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.reports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.reports_id_seq OWNED BY public.reports.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    datoteka text NOT NULL,
    odtis text NOT NULL,
    uporabljen timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: stripe_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.stripe_events (
    id text NOT NULL,
    type text NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE stripe_events; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.stripe_events IS 'Ze obdelani Stripe webhook dogodki (idempotenca, issue #19).';


--
-- Name: table_holds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.table_holds (
    id integer NOT NULL,
    event_id integer NOT NULL,
    table_id integer NOT NULL,
    guest_name text NOT NULL,
    note text,
    created_by_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT table_holds_guest_chk CHECK (((char_length(btrim(guest_name)) >= 1) AND (char_length(btrim(guest_name)) <= 60))),
    CONSTRAINT table_holds_note_chk CHECK (((note IS NULL) OR (char_length(note) <= 200)))
);


--
-- Name: TABLE table_holds; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.table_holds IS 'Rezervacija mize po telefonu (klub jo oznaci sam; ni narocilo, ni prodaja). Osebni podatek: guest_name/note, brise se po koncu dogodka.';


--
-- Name: COLUMN table_holds.guest_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.table_holds.guest_name IS 'Ime gosta, ki je poklical klub (prosto besedilo, ne uporabnik Outly). Samo za osebje kluba.';


--
-- Name: table_holds_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.table_holds_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: table_holds_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.table_holds_id_seq OWNED BY public.table_holds.id;


--
-- Name: table_service; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.table_service (
    id integer NOT NULL,
    event_id integer NOT NULL,
    order_id integer NOT NULL,
    club_id integer NOT NULL,
    table_label text NOT NULL,
    table_seats integer NOT NULL,
    package_name text,
    package_description text,
    scanned_at timestamp with time zone NOT NULL,
    delivered_at timestamp with time zone,
    delivered_by_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE table_service; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.table_service IS 'Strezba VIP mize (038): nastane ob prvem uspesnem skenu vstopnice VIP narocila. Brez kupca: natakar ne sme videti osebnih podatkov (I27).';


--
-- Name: COLUMN table_service.order_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.table_service.order_id IS 'UNIQUE: drugi in naslednji skeni vstopnic istega narocila strezbe ne podvojijo (ON CONFLICT DO NOTHING).';


--
-- Name: COLUMN table_service.delivered_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.table_service.delivered_at IS 'NULL = nedostavljeno. PUT /business/table-service/:id { delivered } nastavi/razveljavi.';


--
-- Name: table_service_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.table_service_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: table_service_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.table_service_id_seq OWNED BY public.table_service.id;


--
-- Name: ticket_transfers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ticket_transfers (
    id bigint NOT NULL,
    ticket_id bigint NOT NULL,
    from_user_id integer,
    to_user_id integer,
    to_email text NOT NULL,
    old_serial uuid NOT NULL,
    new_serial uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    seen_at timestamp with time zone,
    to_guest boolean DEFAULT false NOT NULL,
    age_confirmed_min smallint,
    allow_guest boolean DEFAULT false NOT NULL,
    to_email_norm text
);


--
-- Name: ticket_transfers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ticket_transfers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ticket_transfers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ticket_transfers_id_seq OWNED BY public.ticket_transfers.id;


--
-- Name: tickets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tickets (
    id bigint NOT NULL,
    order_id bigint NOT NULL,
    event_id integer NOT NULL,
    serial uuid DEFAULT gen_random_uuid() NOT NULL,
    status text DEFAULT 'valid'::text NOT NULL,
    used_at timestamp with time zone,
    used_by_user_id integer,
    scan_device text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    holder_user_id integer,
    holder_is_guest boolean DEFAULT false NOT NULL,
    holder_guest_email text,
    holder_guest_mail_sent_at timestamp with time zone,
    holder_guest_mail_claimed_at timestamp with time zone,
    holder_guest_mail_attempts smallint DEFAULT 0 NOT NULL,
    CONSTRAINT tickets_gost_imetnik_chk CHECK ((((NOT holder_is_guest) AND (holder_guest_email IS NULL)) OR (holder_is_guest AND (holder_user_id IS NULL) AND ((holder_guest_email IS NULL) OR ((holder_guest_email = lower(holder_guest_email)) AND (char_length(holder_guest_email) <= 254) AND (POSITION(('@'::text) IN (holder_guest_email)) > 1)))))),
    CONSTRAINT tickets_status_chk CHECK ((status = ANY (ARRAY['valid'::text, 'used'::text, 'void'::text, 'refunded'::text]))),
    CONSTRAINT tickets_used_chk CHECK (((status <> 'used'::text) OR (used_at IS NOT NULL)))
);


--
-- Name: COLUMN tickets.holder_is_guest; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tickets.holder_is_guest IS 'Vstopnico drzi gost (prenos na e-naslov brez racuna). Ostane TRUE tudi po anonimizaciji e-naslova; po prevzemu v racun FALSE.';


--
-- Name: COLUMN tickets.holder_guest_email; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tickets.holder_guest_email IS 'E-naslov gosta imetnika. Osebni podatek; NULL po prevzemu v racun ali konec dogodka + 30 dni.';


--
-- Name: tickets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tickets_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tickets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tickets_id_seq OWNED BY public.tickets.id;


--
-- Name: user_blocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_blocks (
    blocker_id integer NOT NULL,
    blocked_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_blocks_not_self_chk CHECK ((blocker_id <> blocked_id))
);


--
-- Name: TABLE user_blocks; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.user_blocks IS 'Bloki med uporabniki (041): blocker_id je blokiral blocked_id. Velja v obe smeri; blokirani ne izve. Izbris racuna pobrise (CASCADE).';


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    email text NOT NULL,
    password_hash text,
    username text NOT NULL,
    role text DEFAULT 'user'::text NOT NULL,
    avatar_url text,
    email_verified boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    failed_login_count smallint DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    phone text,
    phone_verified boolean DEFAULT false NOT NULL,
    date_of_birth date,
    country character(2),
    genres text[] DEFAULT '{}'::text[] NOT NULL,
    onboarded_at timestamp with time zone,
    supabase_uid uuid,
    share_plans_with_friends boolean DEFAULT true NOT NULL,
    CONSTRAINT users_country_chk CHECK (((country IS NULL) OR (country ~ '^[A-Z]{2}$'::text))),
    CONSTRAINT users_dob_chk CHECK (((date_of_birth IS NULL) OR ((date_of_birth < CURRENT_DATE) AND (date_of_birth > (CURRENT_DATE - '120 years'::interval))))),
    CONSTRAINT users_email_chk CHECK ((POSITION(('@'::text) IN (email)) > 1)),
    CONSTRAINT users_phone_chk CHECK (((phone IS NULL) OR (phone ~ '^\+[1-9][0-9]{7,14}$'::text))),
    CONSTRAINT users_role_chk CHECK ((role = ANY (ARRAY['user'::text, 'business'::text, 'admin'::text, 'backup'::text])))
);


--
-- Name: CONSTRAINT users_role_chk ON users; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON CONSTRAINT users_role_chk ON public.users IS 'Dovoljene vloge: user, business, admin, backup (backup = samo GET /admin/api/export, issue #116).';


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: view_counts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.view_counts (
    club_id integer NOT NULL,
    event_id integer,
    day date NOT NULL,
    count integer DEFAULT 0 NOT NULL
);


--
-- Name: bottle_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bottle_packages ALTER COLUMN id SET DEFAULT nextval('public.bottle_packages_id_seq'::regclass);


--
-- Name: club_event_notifications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_event_notifications ALTER COLUMN id SET DEFAULT nextval('public.club_event_notifications_id_seq'::regclass);


--
-- Name: club_invites id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_invites ALTER COLUMN id SET DEFAULT nextval('public.club_invites_id_seq'::regclass);


--
-- Name: club_members id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_members ALTER COLUMN id SET DEFAULT nextval('public.club_members_id_seq'::regclass);


--
-- Name: club_tables id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_tables ALTER COLUMN id SET DEFAULT nextval('public.club_tables_id_seq'::regclass);


--
-- Name: clubs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clubs ALTER COLUMN id SET DEFAULT nextval('public.clubs_id_seq'::regclass);


--
-- Name: creator_applications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.creator_applications ALTER COLUMN id SET DEFAULT nextval('public.creator_applications_id_seq'::regclass);


--
-- Name: device_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens ALTER COLUMN id SET DEFAULT nextval('public.device_tokens_id_seq'::regclass);


--
-- Name: events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ALTER COLUMN id SET DEFAULT nextval('public.events_id_seq'::regclass);


--
-- Name: friend_requests id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.friend_requests ALTER COLUMN id SET DEFAULT nextval('public.friend_requests_id_seq'::regclass);


--
-- Name: guest_list_members id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_list_members ALTER COLUMN id SET DEFAULT nextval('public.guest_list_members_id_seq'::regclass);


--
-- Name: guest_lists id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_lists ALTER COLUMN id SET DEFAULT nextval('public.guest_lists_id_seq'::regclass);


--
-- Name: orders id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders ALTER COLUMN id SET DEFAULT nextval('public.orders_id_seq'::regclass);


--
-- Name: reports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports ALTER COLUMN id SET DEFAULT nextval('public.reports_id_seq'::regclass);


--
-- Name: table_holds id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_holds ALTER COLUMN id SET DEFAULT nextval('public.table_holds_id_seq'::regclass);


--
-- Name: table_service id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_service ALTER COLUMN id SET DEFAULT nextval('public.table_service_id_seq'::regclass);


--
-- Name: ticket_transfers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket_transfers ALTER COLUMN id SET DEFAULT nextval('public.ticket_transfers_id_seq'::regclass);


--
-- Name: tickets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tickets ALTER COLUMN id SET DEFAULT nextval('public.tickets_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: bottle_packages bottle_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bottle_packages
    ADD CONSTRAINT bottle_packages_pkey PRIMARY KEY (id);


--
-- Name: club_event_notifications club_event_notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_event_notifications
    ADD CONSTRAINT club_event_notifications_pkey PRIMARY KEY (id);


--
-- Name: club_event_notifications club_event_notifications_uniq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_event_notifications
    ADD CONSTRAINT club_event_notifications_uniq UNIQUE (user_id, event_id);


--
-- Name: club_follows club_follows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_follows
    ADD CONSTRAINT club_follows_pkey PRIMARY KEY (club_id, user_id);


--
-- Name: club_invites club_invites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_invites
    ADD CONSTRAINT club_invites_pkey PRIMARY KEY (id);


--
-- Name: club_members club_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_members
    ADD CONSTRAINT club_members_pkey PRIMARY KEY (id);


--
-- Name: club_tables club_tables_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_tables
    ADD CONSTRAINT club_tables_pkey PRIMARY KEY (id);


--
-- Name: clubs clubs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clubs
    ADD CONSTRAINT clubs_pkey PRIMARY KEY (id);


--
-- Name: creator_applications creator_applications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.creator_applications
    ADD CONSTRAINT creator_applications_pkey PRIMARY KEY (id);


--
-- Name: device_tokens device_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT device_tokens_pkey PRIMARY KEY (id);


--
-- Name: device_tokens device_tokens_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT device_tokens_token_key UNIQUE (token);


--
-- Name: event_favorites event_favorites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_favorites
    ADD CONSTRAINT event_favorites_pkey PRIMARY KEY (user_id, event_id);


--
-- Name: event_interest event_interest_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_interest
    ADD CONSTRAINT event_interest_pkey PRIMARY KEY (user_id, event_id);


--
-- Name: event_tables event_tables_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_tables
    ADD CONSTRAINT event_tables_pkey PRIMARY KEY (event_id, table_id);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (id);


--
-- Name: friend_requests friend_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.friend_requests
    ADD CONSTRAINT friend_requests_pkey PRIMARY KEY (id);


--
-- Name: friendships friendships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.friendships
    ADD CONSTRAINT friendships_pkey PRIMARY KEY (user_a, user_b);


--
-- Name: gost_zetoni gost_zetoni_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gost_zetoni
    ADD CONSTRAINT gost_zetoni_pkey PRIMARY KEY (token_hash);


--
-- Name: gost_zetoni_vstopnic gost_zetoni_vstopnic_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gost_zetoni_vstopnic
    ADD CONSTRAINT gost_zetoni_vstopnic_pkey PRIMARY KEY (token_hash);


--
-- Name: guest_list_members guest_list_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_list_members
    ADD CONSTRAINT guest_list_members_pkey PRIMARY KEY (id);


--
-- Name: guest_lists guest_lists_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_lists
    ADD CONSTRAINT guest_lists_pkey PRIMARY KEY (id);


--
-- Name: omejitve omejitve_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.omejitve
    ADD CONSTRAINT omejitve_pkey PRIMARY KEY (kljuc);


--
-- Name: orders orders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (id);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (datoteka);


--
-- Name: stripe_events stripe_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stripe_events
    ADD CONSTRAINT stripe_events_pkey PRIMARY KEY (id);


--
-- Name: table_holds table_holds_event_table_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_holds
    ADD CONSTRAINT table_holds_event_table_key UNIQUE (event_id, table_id);


--
-- Name: table_holds table_holds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_holds
    ADD CONSTRAINT table_holds_pkey PRIMARY KEY (id);


--
-- Name: table_service table_service_order_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_service
    ADD CONSTRAINT table_service_order_id_key UNIQUE (order_id);


--
-- Name: table_service table_service_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_service
    ADD CONSTRAINT table_service_pkey PRIMARY KEY (id);


--
-- Name: ticket_transfers ticket_transfers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket_transfers
    ADD CONSTRAINT ticket_transfers_pkey PRIMARY KEY (id);


--
-- Name: tickets tickets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tickets
    ADD CONSTRAINT tickets_pkey PRIMARY KEY (id);


--
-- Name: user_blocks user_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_blocks
    ADD CONSTRAINT user_blocks_pkey PRIMARY KEY (blocker_id, blocked_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: bottle_packages_club_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX bottle_packages_club_idx ON public.bottle_packages USING btree (club_id) WHERE (archived_at IS NULL);


--
-- Name: ca_email_open_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ca_email_open_key ON public.creator_applications USING btree (lower(email)) WHERE (status = 'new'::text);


--
-- Name: ca_status_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ca_status_created_idx ON public.creator_applications USING btree (status, created_at);


--
-- Name: club_event_notifications_unseen_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX club_event_notifications_unseen_idx ON public.club_event_notifications USING btree (user_id) WHERE (seen_at IS NULL);


--
-- Name: club_follows_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX club_follows_user_idx ON public.club_follows USING btree (user_id, created_at DESC);


--
-- Name: club_invites_pending_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX club_invites_pending_uniq ON public.club_invites USING btree (club_id, user_id) WHERE (status = 'pending'::text);


--
-- Name: club_invites_user_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX club_invites_user_pending_idx ON public.club_invites USING btree (user_id) WHERE (status = 'pending'::text);


--
-- Name: club_members_club_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX club_members_club_idx ON public.club_members USING btree (club_id, role);


--
-- Name: club_members_club_user_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX club_members_club_user_uniq ON public.club_members USING btree (club_id, user_id);


--
-- Name: club_members_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX club_members_user_idx ON public.club_members USING btree (user_id, created_at);


--
-- Name: club_tables_club_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX club_tables_club_idx ON public.club_tables USING btree (club_id) WHERE (archived_at IS NULL);


--
-- Name: club_tables_event_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX club_tables_event_idx ON public.club_tables USING btree (event_id) WHERE (event_id IS NOT NULL);


--
-- Name: club_tables_event_label_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX club_tables_event_label_key ON public.club_tables USING btree (event_id, lower(label)) WHERE ((event_id IS NOT NULL) AND (archived_at IS NULL));


--
-- Name: club_tables_label_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX club_tables_label_key ON public.club_tables USING btree (club_id, lower(label)) WHERE ((event_id IS NULL) AND (archived_at IS NULL));


--
-- Name: clubs_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX clubs_created_idx ON public.clubs USING btree (created_at DESC);


--
-- Name: clubs_hidden_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX clubs_hidden_idx ON public.clubs USING btree (hidden) WHERE hidden;


--
-- Name: clubs_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX clubs_owner_idx ON public.clubs USING btree (owner_user_id);


--
-- Name: clubs_stripe_account_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX clubs_stripe_account_key ON public.clubs USING btree (stripe_account_id) WHERE (stripe_account_id IS NOT NULL);


--
-- Name: device_tokens_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX device_tokens_user_idx ON public.device_tokens USING btree (user_id);


--
-- Name: event_favorites_event_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_favorites_event_idx ON public.event_favorites USING btree (event_id);


--
-- Name: event_interest_event_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_interest_event_idx ON public.event_interest USING btree (event_id);


--
-- Name: event_tables_table_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_tables_table_idx ON public.event_tables USING btree (table_id);


--
-- Name: events_club_start_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_club_start_idx ON public.events USING btree (club_id, start_at);


--
-- Name: events_start_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_start_idx ON public.events USING btree (start_at);


--
-- Name: events_venue_club_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_venue_club_idx ON public.events USING btree (venue_club_id, start_at) WHERE (venue_club_id IS NOT NULL);


--
-- Name: friend_requests_pending_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX friend_requests_pending_uniq ON public.friend_requests USING btree (LEAST(from_user_id, to_user_id), GREATEST(from_user_id, to_user_id)) WHERE (status = 'pending'::text);


--
-- Name: friend_requests_to_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX friend_requests_to_pending_idx ON public.friend_requests USING btree (to_user_id) WHERE (status = 'pending'::text);


--
-- Name: friendships_user_b_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX friendships_user_b_idx ON public.friendships USING btree (user_b);


--
-- Name: gost_zetoni_order_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX gost_zetoni_order_idx ON public.gost_zetoni USING btree (order_id, created_at DESC);


--
-- Name: gost_zetoni_vstopnic_ticket_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX gost_zetoni_vstopnic_ticket_idx ON public.gost_zetoni_vstopnic USING btree (ticket_id, created_at DESC);


--
-- Name: guest_list_members_aktiven_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX guest_list_members_aktiven_key ON public.guest_list_members USING btree (guest_list_id, user_id) WHERE (removed_at IS NULL);


--
-- Name: guest_list_members_neprebrana_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX guest_list_members_neprebrana_idx ON public.guest_list_members USING btree (user_id) WHERE ((seen_at IS NULL) AND (removed_at IS NULL));


--
-- Name: guest_list_members_uporabnik_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX guest_list_members_uporabnik_idx ON public.guest_list_members USING btree (user_id) WHERE (removed_at IS NULL);


--
-- Name: guest_list_members_vstopnica_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX guest_list_members_vstopnica_key ON public.guest_list_members USING btree (ticket_id);


--
-- Name: guest_lists_aktivna_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX guest_lists_aktivna_key ON public.guest_lists USING btree (event_id, host_user_id) WHERE (revoked_at IS NULL);


--
-- Name: guest_lists_dogodek_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX guest_lists_dogodek_idx ON public.guest_lists USING btree (event_id);


--
-- Name: guest_lists_gostitelj_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX guest_lists_gostitelj_idx ON public.guest_lists USING btree (host_user_id) WHERE (revoked_at IS NULL);


--
-- Name: omejitve_okno_do_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX omejitve_okno_do_idx ON public.omejitve USING btree (okno_do);


--
-- Name: orders_checkout_session_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX orders_checkout_session_key ON public.orders USING btree (stripe_checkout_session_id) WHERE (stripe_checkout_session_id IS NOT NULL);


--
-- Name: orders_club_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_club_idx ON public.orders USING btree (club_id, created_at DESC);


--
-- Name: orders_event_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_event_idx ON public.orders USING btree (event_id, status);


--
-- Name: orders_gost_cakajoce_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX orders_gost_cakajoce_key ON public.orders USING btree (guest_email, event_id) WHERE ((guest_email IS NOT NULL) AND (status = 'pending'::text));


--
-- Name: orders_gost_email_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_gost_email_idx ON public.orders USING btree (guest_email) WHERE (guest_email IS NOT NULL);


--
-- Name: orders_gost_idempotency_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX orders_gost_idempotency_key ON public.orders USING btree (guest_email, idempotency_key) WHERE ((guest_email IS NOT NULL) AND (idempotency_key IS NOT NULL));


--
-- Name: orders_gost_poslano_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_gost_poslano_idx ON public.orders USING btree (guest_mail_sent_at) WHERE (guest_mail_sent_at IS NOT NULL);


--
-- Name: orders_gost_posta_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_gost_posta_idx ON public.orders USING btree (id) WHERE ((guest_email IS NOT NULL) AND (guest_mail_sent_at IS NULL) AND (status = 'paid'::text));


--
-- Name: orders_guest_list_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX orders_guest_list_key ON public.orders USING btree (guest_list_id) WHERE (guest_list_id IS NOT NULL);


--
-- Name: orders_idempotency_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX orders_idempotency_key ON public.orders USING btree (user_id, idempotency_key) WHERE (idempotency_key IS NOT NULL);


--
-- Name: orders_miza_dogodek_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX orders_miza_dogodek_key ON public.orders USING btree (event_id, table_id) WHERE ((table_id IS NOT NULL) AND (status = ANY (ARRAY['pending'::text, 'paid'::text, 'partially_refunded'::text])));


--
-- Name: orders_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_pending_idx ON public.orders USING btree (created_at) WHERE (status = 'pending'::text);


--
-- Name: orders_pi_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX orders_pi_key ON public.orders USING btree (stripe_payment_intent_id) WHERE (stripe_payment_intent_id IS NOT NULL);


--
-- Name: orders_public_ref_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX orders_public_ref_key ON public.orders USING btree (public_ref);


--
-- Name: orders_table_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_table_idx ON public.orders USING btree (table_id) WHERE (table_id IS NOT NULL);


--
-- Name: orders_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_user_idx ON public.orders USING btree (user_id, created_at DESC);


--
-- Name: reports_reporter_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX reports_reporter_idx ON public.reports USING btree (reporter_id, created_at DESC) WHERE (reporter_id IS NOT NULL);


--
-- Name: reports_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX reports_status_idx ON public.reports USING btree (status, created_at DESC);


--
-- Name: table_holds_table_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX table_holds_table_idx ON public.table_holds USING btree (table_id);


--
-- Name: table_service_club_event_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX table_service_club_event_idx ON public.table_service USING btree (club_id, event_id, delivered_at);


--
-- Name: ticket_transfers_gost_cas_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ticket_transfers_gost_cas_idx ON public.ticket_transfers USING btree (created_at) WHERE to_guest;


--
-- Name: ticket_transfers_gost_naslov_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ticket_transfers_gost_naslov_idx ON public.ticket_transfers USING btree (to_email_norm, created_at) WHERE allow_guest;


--
-- Name: ticket_transfers_gost_posiljatelj_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ticket_transfers_gost_posiljatelj_idx ON public.ticket_transfers USING btree (from_user_id, created_at) WHERE allow_guest;


--
-- Name: ticket_transfers_ticket_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ticket_transfers_ticket_idx ON public.ticket_transfers USING btree (ticket_id, created_at DESC);


--
-- Name: ticket_transfers_to_unseen_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ticket_transfers_to_unseen_idx ON public.ticket_transfers USING btree (to_user_id) WHERE (seen_at IS NULL);


--
-- Name: tickets_event_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tickets_event_idx ON public.tickets USING btree (event_id, status);


--
-- Name: tickets_gost_email_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tickets_gost_email_idx ON public.tickets USING btree (holder_guest_email) WHERE (holder_guest_email IS NOT NULL);


--
-- Name: tickets_gost_posta_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tickets_gost_posta_idx ON public.tickets USING btree (id) WHERE (holder_is_guest AND (holder_guest_mail_sent_at IS NULL));


--
-- Name: tickets_holder_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tickets_holder_idx ON public.tickets USING btree (holder_user_id) WHERE (holder_user_id IS NOT NULL);


--
-- Name: tickets_order_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tickets_order_idx ON public.tickets USING btree (order_id);


--
-- Name: tickets_serial_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX tickets_serial_key ON public.tickets USING btree (serial);


--
-- Name: user_blocks_blocked_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_blocks_blocked_idx ON public.user_blocks USING btree (blocked_id);


--
-- Name: users_email_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_email_key ON public.users USING btree (email);


--
-- Name: users_genres_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_genres_idx ON public.users USING gin (genres);


--
-- Name: users_phone_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_phone_key ON public.users USING btree (phone) WHERE (phone IS NOT NULL);


--
-- Name: users_supabase_uid_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_supabase_uid_key ON public.users USING btree (supabase_uid) WHERE (supabase_uid IS NOT NULL);


--
-- Name: users_username_lower_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_username_lower_key ON public.users USING btree (lower(username));


--
-- Name: view_counts_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX view_counts_uniq ON public.view_counts USING btree (club_id, COALESCE(event_id, 0), day);


--
-- Name: orders orders_rezerviraj; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER orders_rezerviraj BEFORE INSERT ON public.orders FOR EACH ROW EXECUTE FUNCTION public.rezerviraj_zalogo();


--
-- Name: orders orders_sprosti; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER orders_sprosti AFTER UPDATE OF status ON public.orders FOR EACH ROW EXECUTE FUNCTION public.sprosti_zalogo();


--
-- Name: bottle_packages bottle_packages_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bottle_packages
    ADD CONSTRAINT bottle_packages_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE CASCADE;


--
-- Name: club_event_notifications club_event_notifications_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_event_notifications
    ADD CONSTRAINT club_event_notifications_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE CASCADE;


--
-- Name: club_event_notifications club_event_notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_event_notifications
    ADD CONSTRAINT club_event_notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: club_follows club_follows_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_follows
    ADD CONSTRAINT club_follows_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE CASCADE;


--
-- Name: club_follows club_follows_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_follows
    ADD CONSTRAINT club_follows_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: club_invites club_invites_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_invites
    ADD CONSTRAINT club_invites_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE CASCADE;


--
-- Name: club_invites club_invites_invited_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_invites
    ADD CONSTRAINT club_invites_invited_by_user_id_fkey FOREIGN KEY (invited_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: club_invites club_invites_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_invites
    ADD CONSTRAINT club_invites_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: club_members club_members_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_members
    ADD CONSTRAINT club_members_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE CASCADE;


--
-- Name: club_members club_members_invited_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_members
    ADD CONSTRAINT club_members_invited_by_user_id_fkey FOREIGN KEY (invited_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: club_members club_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_members
    ADD CONSTRAINT club_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: club_tables club_tables_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_tables
    ADD CONSTRAINT club_tables_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE CASCADE;


--
-- Name: club_tables club_tables_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.club_tables
    ADD CONSTRAINT club_tables_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE CASCADE;


--
-- Name: clubs clubs_owner_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clubs
    ADD CONSTRAINT clubs_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: creator_applications creator_applications_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.creator_applications
    ADD CONSTRAINT creator_applications_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE SET NULL;


--
-- Name: creator_applications creator_applications_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.creator_applications
    ADD CONSTRAINT creator_applications_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: creator_applications creator_applications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.creator_applications
    ADD CONSTRAINT creator_applications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: device_tokens device_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT device_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: event_favorites event_favorites_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_favorites
    ADD CONSTRAINT event_favorites_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE CASCADE;


--
-- Name: event_favorites event_favorites_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_favorites
    ADD CONSTRAINT event_favorites_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: event_interest event_interest_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_interest
    ADD CONSTRAINT event_interest_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE CASCADE;


--
-- Name: event_interest event_interest_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_interest
    ADD CONSTRAINT event_interest_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: event_tables event_tables_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_tables
    ADD CONSTRAINT event_tables_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE CASCADE;


--
-- Name: event_tables event_tables_table_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_tables
    ADD CONSTRAINT event_tables_table_id_fkey FOREIGN KEY (table_id) REFERENCES public.club_tables(id) ON DELETE CASCADE;


--
-- Name: events events_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE CASCADE;


--
-- Name: events events_venue_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_venue_club_id_fkey FOREIGN KEY (venue_club_id) REFERENCES public.clubs(id) ON DELETE SET NULL;


--
-- Name: events events_vip_layout_from_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_vip_layout_from_club_id_fkey FOREIGN KEY (vip_layout_from_club_id) REFERENCES public.clubs(id) ON DELETE SET NULL;


--
-- Name: friend_requests friend_requests_from_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.friend_requests
    ADD CONSTRAINT friend_requests_from_user_id_fkey FOREIGN KEY (from_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: friend_requests friend_requests_to_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.friend_requests
    ADD CONSTRAINT friend_requests_to_user_id_fkey FOREIGN KEY (to_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: friendships friendships_user_a_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.friendships
    ADD CONSTRAINT friendships_user_a_fkey FOREIGN KEY (user_a) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: friendships friendships_user_b_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.friendships
    ADD CONSTRAINT friendships_user_b_fkey FOREIGN KEY (user_b) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: gost_zetoni gost_zetoni_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gost_zetoni
    ADD CONSTRAINT gost_zetoni_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(id) ON DELETE CASCADE;


--
-- Name: gost_zetoni_vstopnic gost_zetoni_vstopnic_ticket_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gost_zetoni_vstopnic
    ADD CONSTRAINT gost_zetoni_vstopnic_ticket_id_fkey FOREIGN KEY (ticket_id) REFERENCES public.tickets(id) ON DELETE CASCADE;


--
-- Name: guest_list_members guest_list_members_guest_list_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_list_members
    ADD CONSTRAINT guest_list_members_guest_list_id_fkey FOREIGN KEY (guest_list_id) REFERENCES public.guest_lists(id) ON DELETE CASCADE;


--
-- Name: guest_list_members guest_list_members_ticket_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_list_members
    ADD CONSTRAINT guest_list_members_ticket_id_fkey FOREIGN KEY (ticket_id) REFERENCES public.tickets(id) ON DELETE RESTRICT;


--
-- Name: guest_list_members guest_list_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_list_members
    ADD CONSTRAINT guest_list_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: guest_lists guest_lists_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_lists
    ADD CONSTRAINT guest_lists_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: guest_lists guest_lists_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_lists
    ADD CONSTRAINT guest_lists_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE RESTRICT;


--
-- Name: guest_lists guest_lists_host_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_lists
    ADD CONSTRAINT guest_lists_host_user_id_fkey FOREIGN KEY (host_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: orders orders_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE RESTRICT;


--
-- Name: orders orders_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE RESTRICT;


--
-- Name: orders orders_guest_list_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_guest_list_id_fkey FOREIGN KEY (guest_list_id) REFERENCES public.guest_lists(id) ON DELETE RESTRICT;


--
-- Name: orders orders_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.bottle_packages(id) ON DELETE RESTRICT;


--
-- Name: orders orders_table_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_table_id_fkey FOREIGN KEY (table_id) REFERENCES public.club_tables(id) ON DELETE RESTRICT;


--
-- Name: orders orders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: reports reports_reporter_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_reporter_id_fkey FOREIGN KEY (reporter_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: reports reports_resolved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_resolved_by_fkey FOREIGN KEY (resolved_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: table_holds table_holds_created_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_holds
    ADD CONSTRAINT table_holds_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: table_holds table_holds_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_holds
    ADD CONSTRAINT table_holds_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE CASCADE;


--
-- Name: table_holds table_holds_table_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_holds
    ADD CONSTRAINT table_holds_table_id_fkey FOREIGN KEY (table_id) REFERENCES public.club_tables(id) ON DELETE CASCADE;


--
-- Name: table_service table_service_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_service
    ADD CONSTRAINT table_service_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE CASCADE;


--
-- Name: table_service table_service_delivered_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_service
    ADD CONSTRAINT table_service_delivered_by_user_id_fkey FOREIGN KEY (delivered_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: table_service table_service_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_service
    ADD CONSTRAINT table_service_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE CASCADE;


--
-- Name: table_service table_service_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.table_service
    ADD CONSTRAINT table_service_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(id) ON DELETE CASCADE;


--
-- Name: ticket_transfers ticket_transfers_from_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket_transfers
    ADD CONSTRAINT ticket_transfers_from_user_id_fkey FOREIGN KEY (from_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: ticket_transfers ticket_transfers_ticket_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket_transfers
    ADD CONSTRAINT ticket_transfers_ticket_id_fkey FOREIGN KEY (ticket_id) REFERENCES public.tickets(id) ON DELETE RESTRICT;


--
-- Name: ticket_transfers ticket_transfers_to_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket_transfers
    ADD CONSTRAINT ticket_transfers_to_user_id_fkey FOREIGN KEY (to_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: tickets tickets_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tickets
    ADD CONSTRAINT tickets_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE RESTRICT;


--
-- Name: tickets tickets_holder_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tickets
    ADD CONSTRAINT tickets_holder_user_id_fkey FOREIGN KEY (holder_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: tickets tickets_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tickets
    ADD CONSTRAINT tickets_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(id) ON DELETE RESTRICT;


--
-- Name: tickets tickets_used_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tickets
    ADD CONSTRAINT tickets_used_by_user_id_fkey FOREIGN KEY (used_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: user_blocks user_blocks_blocked_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_blocks
    ADD CONSTRAINT user_blocks_blocked_id_fkey FOREIGN KEY (blocked_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_blocks user_blocks_blocker_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_blocks
    ADD CONSTRAINT user_blocks_blocker_id_fkey FOREIGN KEY (blocker_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: view_counts view_counts_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.view_counts
    ADD CONSTRAINT view_counts_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE CASCADE;


--
-- Name: view_counts view_counts_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.view_counts
    ADD CONSTRAINT view_counts_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict eWqM0o0zcTAGrdYkf9O2phn5BgBcJ95hBB7AuTtELkJWbdfiiTJ1tdPoLSjHnWQ

