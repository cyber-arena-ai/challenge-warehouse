from flask import Blueprint, render_template, request, g, url_for, redirect
from .db import get_db
from .auth import login_required
from time import time
from .iata import get_iata
import python_jwt as jwt
import jwcrypto.jwk as jwk
import datetime 
import base64
from jwcrypto.common import base64url_encode, base64url_decode
import treepoem
from io import BytesIO
import json
from werkzeug.security import check_password_hash, generate_password_hash

main = Blueprint("main", __name__)


@main.route('/')
@login_required
def dieStartseite():
    return render_template('dieStartseite.html')


@main.route('/dasProfil', methods=["GET", "POST"])
@login_required
def dasProfil():
    datenbank = get_db()
    zeiger = datenbank.cursor()
    res = zeiger.execute(
        f"SELECT * FROM users WHERE id == {g.user[0]}")
    res = res.fetchone()
    derBenutzername = res[1]
    dieBeschreibung = res[3]
    res = zeiger.execute(
        f"SELECT * FROM flugscheine WHERE benutzer_identifikation == {g.user[0]}"
    )
    res = res.fetchall()

    def getIdFromTicket(ticket):
        header, claims = jwt.verify_jwt(ticket, get_key(), ['PS256'], ignore_not_implemented=True)
        for k, v in claims.items():
            if k == "flug_id":
                return v
    if request.method == "GET":
        return render_template("dasProfil.html", benutzer=derBenutzername, beschreibung=dieBeschreibung, scheine=res, funkt=getIdFromTicket, änderung=False)
    if request.method == "POST":
        if request.form["ändern"]=="wahr":
            return render_template("dasProfil.html", benutzer=derBenutzername, beschreibung=dieBeschreibung, scheine=res, funkt=getIdFromTicket, änderung=True)
    return render_template("dasProfil.html", benutzer=derBenutzername, beschreibung=dieBeschreibung, scheine=res, funkt=getIdFromTicket, änderung=False)


@main.route('/dieFlüge/<int:seitenzahl>')
@login_required
def dieFlugübersicht(seitenzahl=0):
    # get list of all flights
    pro_seite = 10
    datenbank = get_db()
    zeiger = datenbank.cursor()
    von = pro_seite*seitenzahl
    bis = pro_seite*(seitenzahl+1)
    res = zeiger.execute(f"SELECT * FROM (SELECT ROW_NUMBER() OVER (ORDER BY id DESC) AS row_num, * FROM fluege) WHERE row_num >={von} AND row_num<={bis}")
    res = res.fetchall()
    if (len(res)==0):
        return render_template('dieFlugübersicht.html', fluege=res, no_flights=True, seitenzahl=seitenzahl)
    return render_template('dieFlugübersicht.html', fluege=res, seitenzahl=seitenzahl)



@main.route('/derFlug/<int:dieFlugnummer>')
@login_required
def dieFlugscheinanzeige(dieFlugnummer):
    datenbank = get_db()
    zeiger = datenbank.cursor()
    anfrage = f"SELECT * FROM fluege WHERE {dieFlugnummer}==id"
    res = zeiger.execute(anfrage)
    flug = res.fetchone()
    flugschein = request.args.get("flugschein")
    isVip = False
    if flugschein != "" and flugschein is not None:
        try:
            _, werte = jwt.verify_jwt(flugschein, get_key(), ['PS256'], ignore_not_implemented=True)
            if "vip" in werte.keys():
                isVip = werte["vip"]
        except:
            pass
    if flug==None:
        return redirect(url_for("main.dieFlugübersicht", seitenzahl=0))
    return render_template('dieFluganzeige.html', flug=flug, get_iata=get_iata, vip=isVip)


@main.route('/dieFlugerstellung', methods=['GET', 'POST'])
@login_required
def dieFlugerstellung():
    auszeitzeit = 0 # Should be 60 seconds or something but we disabled it for the checker currently TODO

    if request.method == "GET":
        return render_template('dieFlugerstellung.html', submitted=False)

    if request.method == "POST":
        current_time = int(time())
        if g.user[4] + auszeitzeit >= current_time:
            return render_template('dieFlugerstellung.html', auszeit=True, sekunden=g.user[4]+auszeitzeit-current_time)

        if not check_password_hash(g.user[2], request.form["passwort"]):
            return render_template('dieFlugerstellung.html', passwort=True)
        form_params = ["beschreibung", "von", "zu", "anzahl", "wichtig", "datum", "vip_info"]
        for param in form_params:
            if param not in request.form:
                # TODO REMOVE
                datenbank = get_db()
                zeiger = datenbank.cursor()
                anfrage = "SELECT * FROM fluege;"
                res = zeiger.execute(anfrage)
                main.logger.info(res.fetchall())
                return render_template('dieFlugerstellung.html', submitted=False)

        beschreibung = request.form["beschreibung"]
        von = request.form["von"]
        zu = request.form["zu"]
        anzahl = request.form["anzahl"]
        wichtig = request.form["wichtig"]
        datum = request.form["datum"]
        vip_einsteig_info = request.form["vip_info"]

        if "" in [beschreibung, von, zu, anzahl, wichtig, datum, vip_einsteig_info]:
            return render_template('dieFlugerstellung.html', submitted=False)

        try:
            datum = datum.split("T")
            datum0 = datum[0].split("-")
            datum0.reverse()
            datum0 = ".".join(datum0)
            print(datum0)
            datum = "".join(datum0) + " " + datum[1]
        except:
            datum = "1.3.37 25:00"

        datenbank = get_db()
        zeiger = datenbank.cursor()
        anfrage = "INSERT INTO fluege (beschreibung, ursprung, ziel, platzanzahl, vipanzahl, datum, vergeben_normal, vergeben_vip, vip_einsteig_informationen, ersteller) VALUES ( ?, ?, ?, ?, ?, ?, 0, 0, ?, ?);"
        zeiger.execute(anfrage, (beschreibung, von, zu, anzahl, wichtig, datum, vip_einsteig_info, g.user[1]))
        datenbank.commit()
        flug_identifikation = zeiger.lastrowid

        datenbank = get_db()
        zeiger = datenbank.cursor()
        anfrage = f"UPDATE users SET flug_auszeit = {current_time} WHERE id={g.user[0]}"
        zeiger.execute(anfrage)
        datenbank.commit()

        traglast = {'vip': True, 'flug_id': flug_identifikation}
        token, bild_zeichenkette = ticketGeneration(traglast)
        zeiger = datenbank.cursor()
        anfrage = f"INSERT INTO flugscheine (benutzer_identifikation, schein, bildzeichenkette) VALUES (?,?,?)"
        zeiger.execute(anfrage, (g.user[0], token, bild_zeichenkette))
        datenbank.commit()

        return redirect(f"/derFlug/{flug_identifikation}?flugschein={token}")


def ticketGeneration(traglast):
    schlüssel = get_key()
    token = jwt.generate_jwt(traglast, schlüssel, 'PS256', datetime.timedelta(minutes=525600))
    bild = treepoem.generate_barcode(
        barcode_type="pdf417",
        data=token
    )
    puffer = BytesIO()
    bild.convert("1").save(puffer, format="PNG")
    bild_zeichenkette = base64.b64encode(puffer.getvalue()).decode('utf-8')
    return token, bild_zeichenkette

@main.route('/dasBuchen/<int:id>', methods=["GET", "POST"])
@login_required
def dasBuchen(id):
    if request.method == "POST":
        datenbank = get_db()
        zeiger = datenbank.cursor()
        anfrage = f"SELECT platzanzahl,vergeben_normal FROM fluege WHERE id={id}"
        res = zeiger.execute(anfrage)
        res = res.fetchone()
        if res==None:
            return redirect(url_for("main.dieStartseite"))
        platzanzahl = res[0]
        vergeben = res[1]
        if vergeben<platzanzahl:
            traglast = { 'vip': False, 'flug_id': id}
            token, bild_zeichenkette = ticketGeneration(traglast)

            zeiger = datenbank.cursor()
            anfrage = f"UPDATE fluege SET (vergeben_normal) = (?) WHERE id = {id}"
            zeiger.execute(anfrage, (vergeben+1,))
            datenbank.commit()
        
            zeiger = datenbank.cursor()
            anfrage = f"INSERT INTO flugscheine (benutzer_identifikation, schein, bildzeichenkette) VALUES (?,?,?)"
            zeiger.execute(anfrage, (g.user[0],token,bild_zeichenkette))
            datenbank.commit()

            return redirect("/dasProfil")
        else:
            return redirect(url_for("main.dieStartseite"))
    return redirect(url_for("main.dieStartseite"))



@main.route('/dasKontaktformular')
@login_required
def dasKontaktformular():
    # page that takes input but does nothing but redirect on button press
    return render_template('dasKontaktformular.html')


@main.route('/dasKontaktformular/dieBestätigung')
@login_required
def dieBestätigung():
    # static thank you page
    return render_template('dieBestätigung.html')



@main.route('/dasProfil/Aktualisierung', methods=['POST'])
@login_required
def dieProfilAktualisierung():
    derBenutzername = request.form['benutzername']
    dasPasswort = request.form['passwort']
    dieBeschreibung = request.form['beschreibung']
    derFlugschein = request.form['flugschein']
    dasBisherigePasswort = request.form['passwortalt']
    dieDatenbank = get_db()
    derZeiger = dieDatenbank.cursor()
    derBenutzer = derZeiger.execute(
        f"SELECT * FROM users WHERE id == {g.user[0]}")
    derBenutzer = derBenutzer.fetchone()
    if not check_password_hash(derBenutzer[2], dasBisherigePasswort):
        return render_template("dasProfil.html", benutzer=derBenutzername, beschreibung=dieBeschreibung, änderung=True, fehler_passwort=True)
    if derBenutzername == "":
        derBenutzername = derBenutzer[1]
    if dasPasswort == "":
        dasPasswort = derBenutzer[2]
    else:
        dasPasswort = generate_password_hash(dasPasswort)
    if dieBeschreibung == "":
        dieBeschreibung = derBenutzer[3]
    dieStellungnahme = f"UPDATE users SET (benutzername, passwort, beschreibung) = (?, ?, ?) WHERE id = {g.user[0]};"
    if derFlugschein != "":
        #check if valid
        try:
            jwt.verify_jwt(derFlugschein, get_key(), ['PS256'], ignore_not_implemented=True)
        except:
            return render_template("dasProfil.html", benutzer=derBenutzername, beschreibung=dieBeschreibung, änderung=True, fehler_flugschein=True)
        bild = treepoem.generate_barcode(
                barcode_type="pdf417",
                data=derFlugschein
            )
        puffer = BytesIO()
        bild.convert("1").save(puffer, format="PNG")
        bild_zeichenkette = base64.b64encode(puffer.getvalue()).decode('utf-8')
        anfrage = f"INSERT INTO flugscheine (benutzer_identifikation, schein, bildzeichenkette) VALUES (?,?,?);"
        derZeiger = dieDatenbank.cursor()
        derZeiger.execute(anfrage, (g.user[0], derFlugschein, bild_zeichenkette))
        
    try:
        derZeiger.execute(dieStellungnahme, (derBenutzername, dasPasswort, dieBeschreibung))
        dieDatenbank.commit()
    except:
        derBenutzername = derBenutzer[1]
        dieBeschreibung = derBenutzer[3]
        return render_template("dasProfil.html", benutzer=derBenutzername, beschreibung=dieBeschreibung, änderung=True, fehler_benutzer=True)
    return render_template("dasProfil.html", benutzer=derBenutzername, beschreibung=dieBeschreibung, änderung=True, aktualisiert=True)

def get_key():
    try:
        with open('data/jwtsecret.txt', 'r') as f:
            JWT_KEY = f.read().strip()
            key = json.loads(JWT_KEY)
            return jwk.JWK(**key)
        
    except FileNotFoundError:
        JWT_KEY = jwk.JWK.generate(kty='RSA', size=2048)
        with open('data/jwtsecret.txt', 'w') as f:
            f.write(JWT_KEY.export())
            return JWT_KEY


