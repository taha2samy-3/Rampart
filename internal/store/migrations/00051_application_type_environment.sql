-- +goose Up
-- expand-safe: adds four columns with an empty default and two checks that every existing row already satisfies (they are empty);
-- the old binary neither writes nor reads them, and every row it writes stays valid.
-- An application is one branch of one repository (D140). type says what it is made of: 'repo' is built, '' is an application that
-- is repository-wide, as before ('machine' is designed and refused by the resource until a host source exists). repository and
-- branch name a 'repo' application. environment is where it runs; '' means nobody said, and the score gives that no points.
ALTER TABLE application
    ADD COLUMN type        text NOT NULL DEFAULT '',
    ADD COLUMN repository  text NOT NULL DEFAULT '',
    ADD COLUMN branch      text NOT NULL DEFAULT '',
    ADD COLUMN environment text NOT NULL DEFAULT '';
ALTER TABLE application
    ADD CONSTRAINT application_type_check CHECK (type IN ('', 'repo')),
    ADD CONSTRAINT application_environment_check CHECK (environment IN ('', 'production', 'staging', 'test', 'development'));

-- +goose Down
ALTER TABLE application
    DROP CONSTRAINT IF EXISTS application_type_check,
    DROP CONSTRAINT IF EXISTS application_environment_check;
ALTER TABLE application
    DROP COLUMN IF EXISTS environment,
    DROP COLUMN IF EXISTS branch,
    DROP COLUMN IF EXISTS repository,
    DROP COLUMN IF EXISTS type;
