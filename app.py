from flask import Flask, render_template, request, redirect, url_for
import pymysql

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import base64

app = Flask(__name__)

def get_db():
    connection = pymysql.connect(
        host="localhost",
        user="root",
        passwd="",
        database="wireguard_db"
    )
    return connection

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
def cre_tun():

    # Récupérer les données du formulaire
    user_id    = request.form.get("user_id")
    adresse    = request.form.get("adresse")
    dns        = request.form.get("DNS")
    public_key_serveur = request.form.get("public_key")
    allowed_ips = request.form.get("allowed_ips")
    endpoint   = request.form.get("Endpoint")
    keepalive  = request.form.get("Keepalive")

    # Générer les clés WireGuard
    private_key_obj = X25519PrivateKey.generate()
    public_key_obj  = private_key_obj.public_key()

    private_key = base64.b64encode(
        private_key_obj.private_bytes_raw()
    ).decode("utf-8")

    public_key = base64.b64encode(
        public_key_obj.public_bytes_raw()
    ).decode("utf-8")
    
