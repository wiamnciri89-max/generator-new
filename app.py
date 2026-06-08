from flask import Flask, render_template, request, redirect, url_for
import pymysql

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import base64

import os
from flask import send_file

app = Flask(__name__)

def get_db():
    connection = pymysql.connect(
        host="localhost",
        user="root",
        passwd="",
        database="wireguard_db"
    )
    return connection

@app.route("/create-user", methods=["POST"])
def create_user():

    # 1. Récupérer les données
    prenom     = request.form.get("firstname")  
    nom        = request.form.get("lastname")  
    entreprise = request.form.get("nputEntreprise") 

    # 2. Insérer en base
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO utilisateur (nom, prenom, entreprise) VALUES (%s, %s, %s)",
        (nom, prenom, entreprise) 
    )
    db.commit()
    db.close()

    # 3. Rediriger
    return redirect(url_for("visite")) 

@app.route("/")
def visite():    #la fonction qui s'exécute pour visiter la page
    db = get_db() #ouvre la connexion MySQL
    cursor = db.cursor() #cursol:l'outil qui envoie les requetes SQL

    #Récupère les utilisateurs 
    cursor.execute("SELECT * FROM utilisateur")
    users = cursor.fetchall() #affiche les resultat

    #Récupère les tunnels 
    cursor.execute("SELECT * FROM tunnel") 
    tunnels = cursor.fetchall()

    db.close()
    return render_template("index.html", users=users, tunnels=tunnels)

@app.route("/create-tunnel", methods=["POST"])
def create_tunnel():

    # Récupérer les données du formulaire
    user_id    = request.form.get("user_id")
    adresse    = request.form.get("adresse")
    dns        = request.form.get("DNS")
    public_key_serveur = request.form.get("public_key")
    allowed_ips = request.form.get("allowed_ips")
    endpoint   = request.form.get("Endpoint")
    keepalive  = request.form.get("Keepalive")

    # Générer les clés WireGuard
    private_key_obj = X25519PrivateKey.generate() #crée une clé privée X25519
    public_key_obj  = private_key_obj.public_key() #La clé publique est calculée automatiquement à partir de la clé privée

    # Convertir la clé public en Base64
    private_key = base64.b64encode( #convertit en Base64
        private_key_obj.private_bytes_raw() #récupère la clé brute(32octets)
    ).decode("utf-8")  #transforme les bytes en texte lisible
     
    # Convertir la clé publique en Base64
    public_key = base64.b64encode(  
        public_key_obj.public_bytes_raw()
    ).decode("utf-8")

# 3. Générer le fichier .conf
    conf_content = f"""[Interface]
PrivateKey = {private_key}
Address = {adresse}
DNS = {dns}

[Peer]
PublicKey = {public_key}
AllowedIPs = {allowed_ips}
Endpoint = {endpoint}
PersistentKeepalive = {keepalive}"""

    # 4. Sauvegarder le fichier
    os.makedirs("configs", exist_ok=True)
    nom_fichier = f"tunnel_{user_id}.conf"
    chemin = os.path.join("configs", nom_fichier)
    with open(chemin, "w") as f:
        f.write(conf_content)

    # 5. Insérer en base
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO tunnel (idUti, adresse, dns, privateKey, publicKey, allowedIPs, endpoint, keepalive, fichierConf) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (user_id, adresse, dns, private_key, public_key, allowed_ips, endpoint, keepalive, nom_fichier)
    )
    db.commit()
    db.close()

    # 6. Rediriger
    return redirect(url_for("visite"))

@app.route("/download/<int:id>")
def download(id):
    #recupérer le nom du fichier depuis le base 
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT fichierConf FROM tunnel WHERE idTunnel = %s",(id,))
    tunnel = cursor.fetchone()
    db.close()

    #envoyer le fichier 
    fichier = tunnel[0].strip()  
    chemin = os.path.join("configs", fichier)  
    return send_file(chemin, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
