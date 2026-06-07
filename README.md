

# LAB 19 — Snake : Résolution détaillée (PwnSec CTF 2024 Mobile Hard)

**Cours : Sécurité des applications mobiles**
**Niveau : Hard**

---

## Objectif du challenge

L'application Android implémente plusieurs mécanismes de protection anti-reverse : détection de root, détection d'émulateur, et détection de Frida via une librairie native. Elle lit un fichier YAML depuis le stockage externe et le parse avec une version vulnérable de SnakeYAML (1.33, affectée par CVE-2022-1471).

L'objectif est d'exploiter cette vulnérabilité de désérialisation non sécurisée pour instancier une classe cachée nommée `BigBoss`. Cette classe charge une librairie native et, lorsqu'elle reçoit la bonne chaîne en paramètre, appelle une fonction JNI qui génère et affiche le flag dans les logs Android (logcat).

Contrairement à d'autres challenges, Frida ne peut pas être utilisé directement en raison des détections natives. La solution repose sur du patching statique de l'APK et un payload de désérialisation YAML.

**Techniques principales :** analyse statique (Jadx + apktool), patching Smali pour bypasser les protections anti-debug/anti-root, exploitation de désérialisation SnakeYAML (CVE-2022-1471), envoi d'Intent via ADB, récupération du flag via logcat.

---

## Étape 0 — Préparation de l'environnement

1. Télécharger l'APK du challenge : `Snake.apk`.
2. Installer les outils nécessaires :
   - Jadx-GUI (analyse du code Java décompilé)
   - apktool (décompilation et recompilation en Smali)
   - apksigner ou uber-apk-signer (signature de l'APK patché)
   - Émulateur Android API 28 ou inférieur (Android 9 ou moins) pour une meilleure compatibilité avec les protections du challenge
3. Installer l'APK original pour observer le comportement initial :

```bash
adb install snake.apk
```

L'application se ferme immédiatement si elle détecte un environnement rooté, un émulateur, ou la présence de Frida. Le patching statique est donc obligatoire avant toute tentative d'exploitation.

---

## Étape 1 — Analyse statique approfondie avec Jadx

Ouvrir l'APK dans Jadx-GUI et explorer le code source décompilé.

**Éléments clés à identifier :**

- Package principal : `com.pwnsec.snake`
- Classe d'entrée : `MainActivity`

Dans `MainActivity`, la logique principale (visible dans `onCreate` ou une méthode appelée au démarrage) fonctionne comme suit :

- L'application vérifie la présence d'un extra Intent nommé `SNAKE` dont la valeur doit être exactement `BigBoss`.
- Si cette condition est remplie, elle accède au stockage externe (`/sdcard/` ou `/storage/emulated/0/`), cherche un dossier nommé `snake`, puis un fichier nommé `Skull_Face.yml`.
- Le contenu du fichier YAML est lu et parsé avec SnakeYAML (classe `Yaml`).

**Classe cible : `BigBoss` (`com.pwnsec.snake.BigBoss`)**

Comme visible dans les captures d'écran de l'analyse Jadx :

- Elle charge une librairie native via `System.loadLibrary("snake")`.
- Son constructeur prend une chaîne en paramètre.
- Si la chaîne reçue est exactement `Snaaaaaaaaaaaaaake`, elle appelle `stringFromJNI()` et passe le résultat à `hexToAscii()`, puis affiche le flag via `Log.d("BigBoss: ", ...)`.
- La méthode `hexToAscii()` convertit une chaîne hexadécimale en ASCII caractère par caractère.
- `stringFromJNI()` est déclarée native : la logique de génération du flag réside dans la librairie `.so`.

**Autres protections observées :**

- Détection de root : vérification de `Build.TAGS`, présence de fichiers comme `/system/app/Superuser.apk`, tentative d'exécution de `su`.
- Détection d'émulateur : vérification de propriétés système comme `ro.hardware`, `ro.product.model`.
- Détection de Frida : implémentée dans la librairie native, via inspection des processus ou des ports actifs.

Ces protections rendent toute utilisation directe de Frida ou d'un appareil rooté impossible sans modification préalable de l'APK.

---

## Étape 2 — Patch Smali pour bypasser les détections (Root / Emulator / Frida)

Les détections étant implémentées en Java/Kotlin et compilées en bytecode Dalvik, on utilise apktool pour intervenir au niveau Smali.

**Décompilation :**

```bash
apktool d snake.apk -o snake_smali
cd snake_smali/smali/com/pwnsec/snake/
```

**Méthode de patching :**

1. Repérer dans Jadx les classes contenant les strings de détection : `"root"`, `"su"`, `"emulator"`, `"frida"`, `"test-keys"`, etc.
2. Dans les fichiers Smali correspondants, les checks retournent généralement `true` ou `false` via des instructions `if-nez` ou `if-eqz`.
3. Pour bypasser, deux approches possibles :
   - Remplacer la condition par un `goto` qui saute directement au chemin "safe".
   - Forcer le retour à `0` (false) : insérer `const/4 v0, 0x0` suivi de `return v0` en tête de la méthode de détection.

**Recompilation et signature :**

```bash
apktool b snake_smali -o snake_patched.apk
apksigner sign --ks ton_keystore.jks snake_patched.apk
```

**Installation de la version patchée :**

```bash
adb install -r snake_patched.apk
```

Accorder les permissions `READ_EXTERNAL_STORAGE` et `WRITE_EXTERNAL_STORAGE` si l'application les demande.

Conseil : sauvegarder les fichiers Smali avant toute modification et tester les patches progressivement, méthode par méthode.

---

## Étape 3 — Création du payload YAML (exploitation de CVE-2022-1471)

Créer le dossier cible sur le stockage externe de l'émulateur :

```bash
adb shell mkdir -p /sdcard/Snake
```

Créer localement le fichier `Skull_Face.yml` avec le payload suivant :

```yaml
!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]
```

**Explication du payload :**

- `!!com.pwnsec.snake.BigBoss` : global tag YAML qui demande à SnakeYAML d'instancier directement la classe Java `BigBoss`. Ce comportement est non sécurisé dans les versions antérieures à 2.0 et constitue le cœur de CVE-2022-1471.
- `["Snaaaaaaaaaaaaaake"]` : tableau passé au constructeur lors de la désérialisation. SnakeYAML appelle `new BigBoss("Snaaaaaaaaaaaaaake")`, ce qui déclenche la vérification de la chaîne, l'appel JNI, et l'affichage du flag dans les logs.

Transférer le fichier sur l'appareil :

```bash
adb push Skull_Face.yml /sdcard/Snake/Skull_Face.yml
```

---

## Étape 4 — Lancement de l'application avec l'Intent approprié

Démarrer `MainActivity` en passant l'extra Intent requis :

```bash
adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss
```

L'extra `-e SNAKE BigBoss` satisfait la condition dans `MainActivity`. Cela déclenche la chaîne complète : lecture de `Skull_Face.yml`, parsing SnakeYAML, instanciation de `BigBoss("Snaaaaaaaaaaaaaake")`, appel natif `stringFromJNI()`, conversion `hexToAscii()`, et écriture du flag dans logcat.

---

## Étape 5 — Récupération du flag via logcat

Le flag n'est pas affiché à l'écran. Il est écrit dans les logs système sous le tag `BigBoss` :

```bash
# Filtre ciblé
adb logcat | grep -i "PWNSEC"

# Filtre élargi
adb logcat | grep -i "snake"
```

**Flag obtenu (confirmé par capture logcat) :**

```
PWNSEC{W3'r3_N0t_T00l5_0f_The_g0v3rnm3n7_0R_4ny0n3_3ls3}
```

---

## Flux d'exploitation récapitulatif

```
Intent (SNAKE=BigBoss)
        |
        v
MainActivity lit /sdcard/Snake/Skull_Face.yml
        |
        v
SnakeYAML parse le payload (CVE-2022-1471)
        |
        v
new BigBoss("Snaaaaaaaaaaaaaake") instancié
        |
        v
stringFromJNI() appelé dans la librairie native
        |
        v
hexToAscii() convertit la sortie JNI
        |
        v
Log.d("BigBoss: ", flag) → visible dans logcat
```

---

## Remarques et conseils avancés

- La difficulté principale réside dans l'identification et le contournement de toutes les couches de protection avant de pouvoir déclencher l'exploitation.
- Si le patching Smali est laborieux, commencer par recenser dans Jadx toutes les occurrences de `Build.TAGS`, `su`, `frida` et `isEmulator` pour cibler précisément les méthodes à modifier.
- La fonction native génère le flag dynamiquement : il n'apparaît pas en clair dans l'APK, ce qui justifie le recours à logcat plutôt qu'à une recherche statique de strings.
- Tester sur un émulateur propre, sans root, après patching, pour s'assurer qu'aucune détection résiduelle ne subsiste.
- La note de bas de page visible dans la décompilation Jadx (`/* JADX INFO: loaded from: classes.dex */`) confirme que la classe `BigBoss` est bien présente dans le bytecode principal, non dans un dex secondaire.

---


*Laboratoire développé dans le cadre du cours Sécurité des applications mobiles — PwnSec CTF 2024.*
