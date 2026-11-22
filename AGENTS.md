# Règles du Projet — BahaaIT Network Tools

## 1. Documentation PDF Vivante (Obligatoire à chaque évolution)
L'application dispose d'une documentation officielle compilée au format PDF dans `docs/Documentation_BahaaIT_Network_Tools.pdf`, générée par `docs/generate_documentation_pdf.py`.

**À chaque ajout, modification ou suppression de fonctionnalité** (nouveau module UI, moteur réseau, règle d'intelligence, collecteur SNMP, table SQLite, paramètre de configuration, benchmark, correctif majeur ou changement de version dans `src/utils/updater.py`) :
1. Mettre à jour la ou les sections correspondantes dans `docs/generate_documentation_pdf.py`.
2. Ajouter une entrée dans le **Journal des Versions (Section 9.2)** de `docs/generate_documentation_pdf.py`.
3. Régénérer le PDF :
   ```powershell
   & "C:\Users\user\AppData\Local\Python\pythoncore-3.14-64\python.exe" docs/generate_documentation_pdf.py
   ```
4. Valider la documentation et la non-régression :
   ```powershell
   & "C:\Users\user\AppData\Local\Python\pythoncore-3.14-64\python.exe" -m pytest tests/test_documentation_pdf.py -v --timeout=30
   ```

## 2. Contraintes Techniques
- **Encodage ReportLab** : n'utiliser que des caractères compatibles `cp1252` (WinAnsi) dans `docs/generate_documentation_pdf.py` et `src/utils/pdf_generator.py` (pas d'emojis Unicode ni de flèches mathématiques non supportées par Helvetica ; privilégier `->`, `>=`, `<=`, `•`, `—`, et les formes vectorielles ReportLab).
- **Sécurité des secrets** : ne jamais inscrire de mots de passe SMTP, clés SNMPv3, chaînes de communauté ou jetons en clair dans la documentation, les journaux ou les exports.
- **Tests Pytest** : toujours exécuter les suites avec `--timeout=30`.
