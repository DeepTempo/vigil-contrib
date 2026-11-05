-- What Vigil may do on its own for one kind of alert, keyed by the cold start signature.
-- A kind with no row asks. The transitions are TRANSITIONS in
-- core/storage/models/kind_policy.py.
CREATE TABLE IF NOT EXISTS public.kind_policies (
    signature text NOT NULL,
    mode character varying(8) NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT kind_policies_pkey PRIMARY KEY (signature),
    CONSTRAINT kind_policies_mode_check CHECK (mode IN ('ask', 'close'))
);

CREATE TABLE IF NOT EXISTS public.kind_policy_events (
    id bigserial NOT NULL,
    signature text NOT NULL,
    from_mode character varying(8) NOT NULL,
    to_mode character varying(8) NOT NULL,
    -- The named person who adopted or revoked it.
    actor text NOT NULL,
    -- What the daemon writes when it marks an alert noise under this adoption.
    reason text NOT NULL,
    evidence jsonb NOT NULL,
    clean_labels integer NOT NULL,
    at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT kind_policy_events_pkey PRIMARY KEY (id),
    CONSTRAINT kind_policy_events_signature_fkey FOREIGN KEY (signature)
        REFERENCES public.kind_policies (signature),
    CONSTRAINT kind_policy_events_from_mode_check CHECK (from_mode IN ('ask', 'close')),
    CONSTRAINT kind_policy_events_to_mode_check CHECK (to_mode IN ('ask', 'close')),
    CONSTRAINT kind_policy_events_actor_check CHECK (actor <> ''),
    CONSTRAINT kind_policy_events_reason_check CHECK (reason <> ''),
    CONSTRAINT kind_policy_events_evidence_check
        CHECK (jsonb_typeof(evidence) = 'object' AND evidence <> '{}'::jsonb),
    -- MIN_STRONG_LABELS in core/coldstart/baseline.py. Here too, so no route or tool can
    -- adopt below it.
    CONSTRAINT kind_policy_events_adopt_bar_check
        CHECK (clean_labels >= 0 AND (to_mode <> 'close' OR clean_labels >= 59))
);

CREATE INDEX IF NOT EXISTS idx_kind_policy_events_signature
    ON public.kind_policy_events (signature, id);

-- A policy is revoked, never deleted, and its history is never rewritten.
REVOKE ALL ON TABLE public.kind_policies FROM vigil_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.kind_policies TO vigil_app;
REVOKE ALL ON TABLE public.kind_policy_events FROM vigil_app;
GRANT SELECT, INSERT ON TABLE public.kind_policy_events TO vigil_app;

COMMENT ON TABLE public.kind_policies IS
    'Whether Vigil asks or closes for one kind of alert; kind_policy_events holds who decided it.';
COMMENT ON TABLE public.kind_policy_events IS
    'Append-only: a row each time a person adopted or revoked a close, with the evidence.';
