// Attendre que toute la page HTML soit chargée
document.addEventListener("DOMContentLoaded", function () {

    // Récupérer l'élément qui contient le message d'erreur
    const messageErreur = document.getElementById("message-erreur");

    // Vérifier que le message existe
    if (messageErreur) {

        // Attendre 3 secondes avant de commencer la disparition
        setTimeout(() => {

            // Ajouter une transition fluide
            messageErreur.style.transition = "opacity 0.5s";

            // Rendre le message transparent
            messageErreur.style.opacity = "0";

            // Après l'animation, supprimer le message du HTML
            setTimeout(() => {
                messageErreur.remove();
            }, 500);

        }, 3000); // 3000 ms = 3 secondes

    }

});

setTimeout(function() {
        var msg = document.getElementById("flash-message");
        if (msg) msg.style.display = "none";
    }, 3000);