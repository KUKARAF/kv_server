ALTER TABLE management_keys ADD COLUMN default_limit REAL;
ALTER TABLE management_keys ADD COLUMN default_limit_reset TEXT
    CHECK (default_limit_reset IN ('daily','weekly','monthly'));
