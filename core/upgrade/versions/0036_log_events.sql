-- One row per telemetry event, every source in one schema, with the source's own
-- record kept beside it. A bounded evidence store, not a SIEM: the retention sweep
-- deletes by time. event_id is the caller's stable key, so ingesting a file twice
-- does not store its events twice.
CREATE TABLE IF NOT EXISTS public.log_events (
    event_id character varying(64) NOT NULL,
    "time" timestamp with time zone NOT NULL,
    source character varying(32) NOT NULL,
    event_class character varying(64) DEFAULT '' NOT NULL,
    severity character varying(16) DEFAULT 'info' NOT NULL,
    src_ip character varying(64),
    src_host character varying(255),
    dst_ip character varying(64),
    dst_host character varying(255),
    dst_port integer,
    user_name character varying(128),
    action character varying(64),
    summary text DEFAULT '' NOT NULL,
    mitre character varying(32),
    -- LogLM's anomaly score. Null without LogLM, and the Logs page says so.
    loglm double precision,
    case_id character varying(50),
    tags jsonb DEFAULT '[]'::jsonb NOT NULL,
    raw jsonb DEFAULT '{}'::jsonb NOT NULL,
    search_text text DEFAULT '' NOT NULL,
    CONSTRAINT log_events_pkey PRIMARY KEY (event_id),
    -- Evidence outlives the case that claimed it, until retention takes it.
    CONSTRAINT log_events_case_id_fkey FOREIGN KEY (case_id)
        REFERENCES public.cases (case_id) ON DELETE SET NULL,
    CONSTRAINT log_events_severity_check
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    CONSTRAINT log_events_loglm_check CHECK (loglm >= 0 AND loglm <= 1)
);

CREATE INDEX IF NOT EXISTS ix_log_events_time
    ON public.log_events USING btree ("time");
CREATE INDEX IF NOT EXISTS ix_log_events_source_time
    ON public.log_events USING btree (source, "time");
CREATE INDEX IF NOT EXISTS ix_log_events_case_id
    ON public.log_events USING btree (case_id);

COMMENT ON TABLE public.log_events IS
    'Telemetry events in one schema, for Logs, the entity graph and rule replay. Bounded by retention.';
