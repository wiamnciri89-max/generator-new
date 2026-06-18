from flask import Flask, render_template, request, redirect, url_for, send_file
import pymysql
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import base64
import os
from flask import flash


app = Flask(__name__)
app.secret_key = "wireguard_secret_key"   


# Connexion à la base de données
def get_db():
    connection = pymysql.connect(
        host="localhost",
        user="root",
        passwd="",
        database="wireguard_db" 
    )
    return connection


# Fonction : Valider l'adresse IP
def valider_ip(adresse):
    # Sépare l'adresse du masque 
    parties = adresse.split("/")
    if len(parties) != 2:
        return False
    ip = parties[0]
    masque = parties[1]

    if not masque.isdigit():
        return False

    if int(masque) < 0 or int(masque) > 32:
        return False
    
    # Sépare les 4 blocs
    blocs = ip.split(".")
    
    # Vérifie qu'il y a exactement 4 blocs
    if len(blocs) != 4:
        return False
    
    # Vérifie chaque bloc
    for bloc in blocs:
        if not bloc.isdigit():  # doit être un nombre
            return False
        if int(bloc) < 0 or int(bloc) > 255:
            return False
    return True

# Valider le DNS sans masque
def valider_dns(dns):
    blocs = dns.split(".")
    if len(blocs) != 4:
        return False
    for bloc in blocs:
        if not bloc.isdigit():
            return False
        if int(bloc) < 0 or int(bloc) > 255:
            return False
    return True


# Fonction : Générer les clés WireGuard
def generate_wireguard_keys():
    # Générer la clé privée
    private_key_obj = X25519PrivateKey.generate()  # crée une clé privée X25519
    public_key_obj  = private_key_obj.public_key() # La clé publique est calculée automatiquement à partir de la clé privée

    # Convertir la clé privée en Base64
    private_key = base64.b64encode(                # convertit en Base64
        private_key_obj.private_bytes_raw()        # récupère la clé brute (32 octets)
    ).decode("utf-8")                              # transforme les bytes en texte lisible

    # Convertir la clé publique en Base64
    public_key = base64.b64encode(
        public_key_obj.public_bytes_raw()
    ).decode("utf-8")

    return private_key, public_key


# Fonction : Générer le fichier .conf
def generate_conf(private_key, adresse, dns, public_key, allowedIPs, endpoint):
    # Générer le fichier .conf
    return f"""[Interface]
PrivateKey = {private_key}
Address = {adresse}
DNS = {dns}

[Peer]
PublicKey = {public_key}
AllowedIPs = {allowedIPs}
Endpoint = {endpoint}
PersistentKeepalive = 25
"""


# Page principale
@app.route("/")
def visite():
    db = get_db()
    cursor = db.cursor()

    # Récupère le mot recherché dans l'URL
    recherche = request.args.get("recherche", "").strip()

    # Récupère les utilisateurs
    if recherche:
        cursor.execute("""
            SELECT * FROM utilisateur
            WHERE nom LIKE %s
            OR prenom LIKE %s
            OR entreprise LIKE %s
        """, (f"%{recherche}%", f"%{recherche}%", f"%{recherche}%"))
    else:
        cursor.execute("SELECT * FROM utilisateur")

    users = cursor.fetchall()

    # Récupère les tunnels liés aux utilisateurs trouvés
    if recherche:
        cursor.execute("""
            SELECT t.idTunnel, t.idUti, t.adresse, t.dns, t.privateKey, 
                t.publicKey, t.allowedIPs, t.endpoint, t.keepalive, t.fichierConf
            FROM tunnel t
            JOIN utilisateur u ON t.idUti = u.idUti
            WHERE u.nom LIKE %s
            OR u.prenom LIKE %s
            OR u.entreprise LIKE %s
        """, (f"%{recherche}%", f"%{recherche}%", f"%{recherche}%"))
    else:
        cursor.execute("""
            SELECT idTunnel, idUti, adresse, dns, privateKey, 
                publicKey, allowedIPs, endpoint, keepalive, fichierConf
            FROM tunnel
        """)

    tunnels = cursor.fetchall() #récupère toutes les lignes d'un ensemble de résultats de requête et renvoie une liste de tuple
    db.close()

    # Gestion du bouton "modifier"
    modifier_id = request.args.get("modifier")
    tunnel_a_modifier = None

    if modifier_id:
        for t in tunnels:
            if t[0] == int(modifier_id):
                tunnel_a_modifier = t
                break

    return render_template(
        "index.html",
        users=users,
        tunnels=tunnels,
        tunnel_a_modifier=tunnel_a_modifier,
        recherche=recherche
    )


# Création utilisateur
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

    # message : uti creer
    flash("✅ Utilisateur créé avec succès !", "success")

    # 3. Rediriger
    return redirect(url_for("visite"))


# Création tunnel
@app.route("/create-tunnel", methods=["POST"])
def create_tunnel():

    # Récupérer les données du formulaire
    user_id    = request.form.get("user_id")
    adresse    = request.form.get("adresse")
    dns        = request.form.get("DNS")
    allowedIPs = request.form.get("allowedIPs") 
    endpoint   = request.form.get("Endpoint")
    
    # Le remlis obligatoires des champs
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM utilisateur")
    users = cursor.fetchall()

    cursor.execute("""
        SELECT idTunnel, idUti, adresse, dns,
               privateKey, publicKey,
               allowedIPs, endpoint,
               keepalive, fichierConf
        FROM tunnel
    """)
    tunnels = cursor.fetchall()

    # Vérifier que tous les champs sont remplis
    if not all([adresse, dns, allowedIPs, endpoint]):

        return render_template(
            "index.html",
            erreur="Tous les champs sont obligatoires !",
            users=users,
            tunnels=tunnels,
            tunnel_a_modifier=None,
            recherche=""
        )

    if not valider_endpoint(endpoint):

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM utilisateur")
        users = cursor.fetchall()

        cursor.execute("""
            SELECT idTunnel, idUti, adresse, dns, privateKey,
                publicKey, allowedIPs, endpoint, keepalive, fichierConf
            FROM tunnel
        """)
        tunnels = cursor.fetchall()

        db.close()

        return render_template(
        "index.html",
        erreur="Endpoint invalide ! Format attendu : adresse:port (exemple : IP_ou_nom_de_domaine:port)",
        users=users,
        tunnels=tunnels,
        recherche=""
        )

    # Valider l'adresse 
    if not valider_ip(adresse):
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM utilisateur")
        users = cursor.fetchall()
        cursor.execute("""
            SELECT idTunnel, idUti, adresse, dns, privateKey, 
                   publicKey, allowedIPs, endpoint, keepalive, fichierConf
            FROM tunnel
        """)
        tunnels = cursor.fetchall()
        db.close()

        return render_template(
            "index.html",
            erreur="Adresse IP invalide ! Format attendu : 0-255.0-255.0-255.0-255/0-32",
            users=users,
            tunnels=tunnels,
            tunnel_a_modifier=None,
            recherche=""
        )
    
    # Valider DNS 
    if not valider_dns(dns):
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM utilisateur")
        users = cursor.fetchall()
        cursor.execute("""
            SELECT idTunnel, idUti, adresse, dns, privateKey, 
                   publicKey, allowedIPs, endpoint, keepalive, fichierConf
            FROM tunnel
        """)
        tunnels = cursor.fetchall()
        db.close()

        return render_template(
            "index.html",
            erreur="DNS invalide ! Format attendu : 0-255.0-255.0-255.0-255",
            users=users,
            tunnels=tunnels,
            tunnel_a_modifier=None,
            recherche=""
        )
    
    # Récupérer les données du formulaire
    public_key_serveur = request.form.get("public_key")  # clé du serveur    

    # Générer les clés WireGuard
    private_key, _ = generate_wireguard_keys()

    # Générer le fichier .conf
    conf_content = generate_conf(
        private_key,
        adresse,
        dns,
        public_key_serveur,
        allowedIPs,
        endpoint,
    )

    # Sauvegarder le fichier
    os.makedirs("configs", exist_ok=True)
    nom_fichier = f"tunnel_{user_id}.conf"
    chemin = os.path.join("configs", nom_fichier)
    with open(chemin, "w") as f:
        f.write(conf_content)

    # Insérer en base
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO tunnel (idUti, adresse, dns, privateKey, publicKey, allowedIPs, endpoint, keepalive, fichierConf) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (user_id, adresse, dns, private_key, public_key_serveur, allowedIPs, endpoint, 25, nom_fichier)
    )
    db.commit()
    db.close()

    #message : tun creer
    flash("✅ Tunnel créé avec succès !", "success")         

    # Rediriger
    return redirect(url_for("visite"))


# Bouton télécharger
@app.route("/download/<int:id>")
def download(id):

    # Récupérer le nom du fichier depuis la base
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT fichierConf FROM tunnel WHERE idTunnel = %s", (id,))
    tunnel = cursor.fetchone()
    db.close()

    # Envoyer le fichier
    fichier = tunnel[0].strip()
    chemin = os.path.join("configs", fichier)
    return send_file(chemin, as_attachment=True)


# Bouton supprimer
@app.route("/delete/<int:id>")
def delete(id):

    db = get_db()
    cursor = db.cursor()

    # 1. Récupérer le fichier .conf
    cursor.execute(
        "SELECT fichierConf FROM tunnel WHERE idTunnel = %s", (id,)
    )
    tunnel = cursor.fetchone()

    # 2. Supprimer le fichier .conf
    if tunnel:
        chemin = os.path.join("configs", tunnel[0])
        if os.path.exists(chemin):
            os.remove(chemin)

    # 3. Supprimer de la base
    cursor.execute(
        "DELETE FROM tunnel WHERE idTunnel = %s", (id,)
    )
    db.commit()
    db.close()

    #message : supprimer 
    flash("🗑️ Tunnel supprimé !", "success") 

    # 4. Rediriger
    return redirect(url_for("visite"))


# Bouton modifier
@app.route("/modify/<int:id>", methods=["POST"])
def modify(id):

    adresse    = request.form.get("adresse")
    dns        = request.form.get("DNS")
    allowedIPs = request.form.get("allowedIPs")
    endpoint   = request.form.get("Endpoint")

    db = get_db()
    cursor = db.cursor()

    # Charger les données nécessaires pour réafficher la page en cas d'erreur
    cursor.execute("SELECT * FROM utilisateur")
    users = cursor.fetchall()

    cursor.execute("""
            SELECT idTunnel, idUti, adresse, dns,
                privateKey, publicKey,
                allowedIPs, endpoint,
                keepalive, fichierConf
            FROM tunnel
            """)
    tunnels = cursor.fetchall()

    if not valider_endpoint(endpoint):

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM utilisateur")
        users = cursor.fetchall()

        cursor.execute("""
            SELECT idTunnel, idUti, adresse, dns, privateKey,
                publicKey, allowedIPs, endpoint, keepalive, fichierConf
            FROM tunnel
        """)
        tunnels = cursor.fetchall()

        db.close()

        return render_template(
            "index.html",
            erreur="Endpoint invalide ! Format attendu : adresse:port (exemple : IP_ou_nom_de_domaine:port)",
            users=users,
            tunnels=tunnels,
            tunnel_a_modifier=None,
            recherche=""
        )

# Valider l'adresse 
    if not valider_ip(adresse):

        return render_template(
            "index.html",
            erreur="Adresse IP invalide ! Format attendu : 0-255.0-255.0-255.0-255/0-32",
            users=users,
            tunnels=tunnels,
            tunnel_a_modifier=None,
            recherche=""
        )
    
    # Valider DNS 
    if not valider_dns(dns):
        db.close()

        return render_template(
            "index.html",
            erreur="DNS invalide ! Format attendu : 0-255.0-255.0-255.0-255",
            users=users,
            tunnels=tunnels,
            tunnel_a_modifier=None,
            recherche=""
        )
       # Vérifier que le tunnel existe
    cursor.execute(
        "SELECT idTunnel FROM tunnel WHERE idTunnel=%s",
        (id,)
    )

    tunnel = cursor.fetchone()

    if not tunnel:
        db.close()
        return "Tunnel introuvable", 404

    # Mise à jour
    cursor.execute(
        """
        UPDATE tunnel
        SET adresse=%s,
            dns=%s,
            allowedIPs=%s,
            endpoint=%s
        WHERE idTunnel=%s
        """,
        (adresse, dns, allowedIPs, endpoint, id)
    )

    db.commit()
    db.close()
    
    #message : modifier
    flash("✏️ Tunnel modifié avec succès !", "success") 
    
    return redirect(url_for("visite"))

#valider l'endpoint
def valider_endpoint(endpoint):
    #separe l'endpoint en 2 parties 
    parties = endpoint.split(":")

    #verifier qu'il y a excatement 2 parties 
    if len(parties) != 2:
        return False
    
    hote = parties[0]
    port = parties[1]

    #vérifier que l'hote n'est pas vide 
    if len(hote.strip()) == 0:
        return False
    
    #vérifie que le port est un nombre 
    if not port.isdigit():
        return False 
    
    #verifiernque le port est entre 1 et 65535
    if int(port) < 1 or int(port) > 65535 :
        return False
    
    return True


# Lancer l'application
if __name__ == "__main__":
    app.run(debug=True)