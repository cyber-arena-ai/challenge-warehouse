CREATE TABLE IF NOT EXISTS fluege(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    beschreibung TEXT NOT NULL,
    ursprung TEXT NOT NULL,
    ziel TEXT NOT NULL,
    platzanzahl INTEGER NOT NULL,
    vipanzahl INTEGER NOT NULL,
    datum TEXT NOT NULL,
    vergeben_normal INTEGER NOT NULL,
    vergeben_vip INTEGER NOT NULL,
    vip_einsteig_informationen TEXT NOT NULL,
    ersteller TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    benutzername TEXT UNIQUE NOT NULL,
    passwort TEXT NOT NULL,
    beschreibung TEXT NOT NULL,
    flug_auszeit INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS flugscheine(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    benutzer_identifikation INTEGER NOT NULL,
    schein TEXT NOT NULL,
    bildzeichenkette TEXT NOT NULL
);