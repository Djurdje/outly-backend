-- =============================================================================
-- Outly — shema podatkovne baze (GENERIRANA, ne urejaj rocno)
-- =============================================================================
-- Vir resnice so migracije v db/migracije/ (poganja jih db/migrate.js ob vsakem
-- deployu). Ta datoteka je izvoz sheme (pg_dump --schema-only) iz baze, na
-- kateri so bile pognane vse migracije 000–008, in sluzi samo za branje:
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
    CONSTRAINT clubs_coords_chk CHECK (((lat IS NULL) = (lng IS NULL))),
    CONSTRAINT clubs_lat_chk CHECK (((lat IS NULL) OR ((lat >= ('-90'::integer)::double precision) AND (lat <= (90)::double precision)))),
    CONSTRAINT clubs_lng_chk CHECK (((lng IS NULL) OR ((lng >= ('-180'::integer)::double precision) AND (lng <= (180)::double precision)))),
    CONSTRAINT clubs_min_age_chk CHECK (((min_age >= 0) AND (min_age <= 99))),
    CONSTRAINT clubs_name_chk CHECK ((length(TRIM(BOTH FROM name)) > 0))
);


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
-- Name: email_verification_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_verification_codes (
    id integer NOT NULL,
    user_id integer NOT NULL,
    code_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    attempts smallint DEFAULT 0 NOT NULL
);


--
-- Name: email_verification_codes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.email_verification_codes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: email_verification_codes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.email_verification_codes_id_seq OWNED BY public.email_verification_codes.id;


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
    CONSTRAINT events_capacity_chk CHECK (((capacity IS NULL) OR (capacity > 0))),
    CONSTRAINT events_end_chk CHECK (((end_at IS NULL) OR (end_at > start_at))),
    CONSTRAINT events_min_age_chk CHECK (((min_age >= 0) AND (min_age <= 99))),
    CONSTRAINT events_price_chk CHECK (((ticket_price_cents IS NULL) OR (ticket_price_cents >= 0))),
    CONSTRAINT events_sales_window_chk CHECK (((sales_close_at IS NULL) OR (sales_open_at IS NULL) OR (sales_close_at > sales_open_at))),
    CONSTRAINT events_sold_chk CHECK (((sold_count >= 0) AND ((capacity IS NULL) OR (sold_count <= capacity)))),
    CONSTRAINT events_status_chk CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'cancelled'::text]))),
    CONSTRAINT events_title_chk CHECK ((length(TRIM(BOTH FROM title)) > 0)),
    CONSTRAINT events_vat_chk CHECK (((vat_rate IS NULL) OR ((vat_rate >= (0)::numeric) AND (vat_rate < (1)::numeric))))
);


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
    CONSTRAINT orders_fee_chk CHECK (((application_fee_cents >= 0) AND (application_fee_cents <= total_cents))),
    CONSTRAINT orders_paid_chk CHECK (((status <> 'paid'::text) OR (paid_at IS NOT NULL))),
    CONSTRAINT orders_price_chk CHECK (((unit_price_cents >= 0) AND (total_cents >= 0))),
    CONSTRAINT orders_qty_chk CHECK (((quantity > 0) AND (quantity <= 20))),
    CONSTRAINT orders_refund_chk CHECK (((refunded_cents >= 0) AND (refunded_cents <= total_cents))),
    CONSTRAINT orders_status_chk CHECK ((status = ANY (ARRAY['pending'::text, 'paid'::text, 'failed'::text, 'cancelled'::text, 'refunded'::text, 'partially_refunded'::text]))),
    CONSTRAINT orders_total_chk CHECK ((total_cents = (unit_price_cents * quantity)))
);


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
-- Name: password_reset_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_reset_codes (
    id integer NOT NULL,
    user_id integer NOT NULL,
    code_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    attempts smallint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: password_reset_codes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.password_reset_codes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: password_reset_codes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.password_reset_codes_id_seq OWNED BY public.password_reset_codes.id;


--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    token_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    replaced_by integer,
    device text DEFAULT ''::text NOT NULL
);


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.refresh_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.refresh_tokens_id_seq OWNED BY public.refresh_tokens.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    datoteka text NOT NULL,
    odtis text NOT NULL,
    uporabljen timestamp with time zone DEFAULT now() NOT NULL
);


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
    created_at timestamp with time zone DEFAULT now() NOT NULL
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
    CONSTRAINT tickets_status_chk CHECK ((status = ANY (ARRAY['valid'::text, 'used'::text, 'void'::text, 'refunded'::text]))),
    CONSTRAINT tickets_used_chk CHECK (((status <> 'used'::text) OR (used_at IS NOT NULL)))
);


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
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    email text NOT NULL,
    password_hash text NOT NULL,
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
    CONSTRAINT users_country_chk CHECK (((country IS NULL) OR (country ~ '^[A-Z]{2}$'::text))),
    CONSTRAINT users_dob_chk CHECK (((date_of_birth IS NULL) OR ((date_of_birth < CURRENT_DATE) AND (date_of_birth > (CURRENT_DATE - '120 years'::interval))))),
    CONSTRAINT users_email_chk CHECK ((POSITION(('@'::text) IN (email)) > 1)),
    CONSTRAINT users_phone_chk CHECK (((phone IS NULL) OR (phone ~ '^\+[1-9][0-9]{7,14}$'::text))),
    CONSTRAINT users_role_chk CHECK ((role = ANY (ARRAY['user'::text, 'business'::text, 'admin'::text])))
);


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
-- Name: clubs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clubs ALTER COLUMN id SET DEFAULT nextval('public.clubs_id_seq'::regclass);


--
-- Name: creator_applications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.creator_applications ALTER COLUMN id SET DEFAULT nextval('public.creator_applications_id_seq'::regclass);


--
-- Name: email_verification_codes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verification_codes ALTER COLUMN id SET DEFAULT nextval('public.email_verification_codes_id_seq'::regclass);


--
-- Name: events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ALTER COLUMN id SET DEFAULT nextval('public.events_id_seq'::regclass);


--
-- Name: orders id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders ALTER COLUMN id SET DEFAULT nextval('public.orders_id_seq'::regclass);


--
-- Name: password_reset_codes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_codes ALTER COLUMN id SET DEFAULT nextval('public.password_reset_codes_id_seq'::regclass);


--
-- Name: refresh_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens ALTER COLUMN id SET DEFAULT nextval('public.refresh_tokens_id_seq'::regclass);


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
-- Name: email_verification_codes email_verification_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verification_codes
    ADD CONSTRAINT email_verification_codes_pkey PRIMARY KEY (id);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (id);


--
-- Name: orders orders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (id);


--
-- Name: password_reset_codes password_reset_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_codes
    ADD CONSTRAINT password_reset_codes_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (datoteka);


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
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: ca_email_open_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ca_email_open_key ON public.creator_applications USING btree (lower(email)) WHERE (status = 'new'::text);


--
-- Name: ca_status_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ca_status_created_idx ON public.creator_applications USING btree (status, created_at);


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
-- Name: evc_user_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX evc_user_active_idx ON public.email_verification_codes USING btree (user_id, created_at DESC) WHERE (used_at IS NULL);


--
-- Name: events_club_start_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_club_start_idx ON public.events USING btree (club_id, start_at);


--
-- Name: events_start_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_start_idx ON public.events USING btree (start_at);


--
-- Name: orders_club_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_club_idx ON public.orders USING btree (club_id, created_at DESC);


--
-- Name: orders_event_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_event_idx ON public.orders USING btree (event_id, status);


--
-- Name: orders_pi_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX orders_pi_key ON public.orders USING btree (stripe_payment_intent_id) WHERE (stripe_payment_intent_id IS NOT NULL);


--
-- Name: orders_public_ref_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX orders_public_ref_key ON public.orders USING btree (public_ref);


--
-- Name: orders_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orders_user_idx ON public.orders USING btree (user_id, created_at DESC);


--
-- Name: prc_user_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX prc_user_active_idx ON public.password_reset_codes USING btree (user_id, created_at DESC) WHERE (used_at IS NULL);


--
-- Name: refresh_tokens_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX refresh_tokens_user_idx ON public.refresh_tokens USING btree (user_id, revoked_at);


--
-- Name: ticket_transfers_ticket_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ticket_transfers_ticket_idx ON public.ticket_transfers USING btree (ticket_id, created_at DESC);


--
-- Name: tickets_event_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tickets_event_idx ON public.tickets USING btree (event_id, status);


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
-- Name: users_username_lower_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_username_lower_key ON public.users USING btree (lower(username));


--
-- Name: orders orders_rezerviraj; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER orders_rezerviraj BEFORE INSERT ON public.orders FOR EACH ROW EXECUTE FUNCTION public.rezerviraj_zalogo();


--
-- Name: orders orders_sprosti; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER orders_sprosti AFTER UPDATE OF status ON public.orders FOR EACH ROW EXECUTE FUNCTION public.sprosti_zalogo();


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
-- Name: email_verification_codes email_verification_codes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verification_codes
    ADD CONSTRAINT email_verification_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: events events_club_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_club_id_fkey FOREIGN KEY (club_id) REFERENCES public.clubs(id) ON DELETE CASCADE;


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
-- Name: orders orders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: password_reset_codes password_reset_codes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_codes
    ADD CONSTRAINT password_reset_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_replaced_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_replaced_by_fkey FOREIGN KEY (replaced_by) REFERENCES public.refresh_tokens(id) ON DELETE SET NULL;


--
-- Name: refresh_tokens refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


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
-- PostgreSQL database dump complete
--


