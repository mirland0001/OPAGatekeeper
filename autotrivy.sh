#!/bin/bash

# Script: trivy-scan-report.sh
# Version corrigée sans problèmes de syntaxe
# Génère un rapport HTML à partir des résultats de Trivy

# Couleurs pour le terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Variables par défaut
OUTPUT_FILE="trivy-report.html"
SCAN_DIR="."

# Vérifier que Trivy est installé
check_trivy() {
    if ! command -v trivy &> /dev/null; then
        echo -e "${RED}Erreur: Trivy n'est pas installé.${NC}"
        echo "Installez Trivy avec:"
        echo "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
        exit 1
    fi
}

# Afficher l'aide
show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -o FILE    Fichier de sortie HTML (défaut: trivy-report.html)"
    echo "  -d DIR     Répertoire à scanner (défaut: courant)"
    echo "  -h         Affiche cette aide"
    exit 0
}

# Traiter les arguments
while getopts ":o:d:h" opt; do
    case $opt in
        o) OUTPUT_FILE="$OPTARG" ;;
        d) SCAN_DIR="$OPTARG" ;;
        h) show_help ;;
        \?) echo -e "${RED}Option invalide: -$OPTARG${NC}" >&2; exit 1 ;;
        :) echo -e "${RED}Option -$OPTARG requiert un argument.${NC}" >&2; exit 1 ;;
    esac
done

# Vérifier le répertoire
if [ ! -d "$SCAN_DIR" ]; then
    echo -e "${RED}Erreur: Répertoire '$SCAN_DIR' introuvable.${NC}"
    exit 1
fi

# Générer le rapport HTML
generate_report() {
    local json_file="$1"
    local html_file="$2"
    
    # En-tête HTML
    cat <<EOF > "$html_file"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Rapport Trivy</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }
        h1 { color: #333; }
        .finding { margin-bottom: 15px; padding: 10px; border-left: 4px solid; }
        .critical { border-color: #dc3545; background-color: #f8d7da; }
        .high { border-color: #fd7e14; background-color: #fff3cd; }
        .medium { border-color: #ffc107; background-color: #fff3cd; }
        .low { border-color: #28a745; background-color: #d4edda; }
        .severity { font-weight: bold; padding: 3px 6px; border-radius: 3px; color: white; }
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; }
        .severity-low { background-color: #28a745; }
        .code-block { background: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Rapport de Scan Trivy</h1>
    <p>Généré le $(date)</p>
    
    <h2>Résumé</h2>
    <table>
        <tr>
            <th>Fichier</th>
            <th>Type</th>
            <th>Total</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
        </tr>
EOF

    # Générer le résumé
    jq -r '.Results[] | select(.Misconfigurations != null) | 
        "        <tr>
            <td>\(.Target)</td>
            <td>\(.Type)</td>
            <td>\(.Misconfigurations | length)</td>
            <td>\([.Misconfigurations[] | select(.Severity == "CRITICAL")] | length)</td>
            <td>\([.Misconfigurations[] | select(.Severity == "HIGH")] | length)</td>
            <td>\([.Misconfigurations[] | select(.Severity == "MEDIUM")] | length)</td>
            <td>\([.Misconfigurations[] | select(.Severity == "LOW")] | length)</td>
        </tr>"' "$json_file" >> "$html_file"

    echo "    </table>" >> "$html_file"

    # Générer les détails des findings
    jq -r '.Results[] | select(.Misconfigurations != null and (.Misconfigurations | length) > 0) | 
        "    <h2>\(.Target) (\(.Type))</h2>
        <p>\(.Misconfigurations | length) problèmes détectés</p>"' "$json_file" >> "$html_file"

    # Détails de chaque finding (version simplifiée)
    jq -r '.Results[] | select(.Misconfigurations != null) | .Target as $target | .Misconfigurations[] | 
        "<div class=\"finding " + (.Severity | ascii_downcase) + "\">" +
        "<h3><span class=\"severity severity-" + (.Severity | ascii_downcase) + "\">" + .Severity + "</span> " + .Title + " (ID: " + .ID + ")</h3>" +
        "<p>" + .Description + "</p>" +
        "<p>Plus d\\&#39;informations: <a href=\"" + .PrimaryURL + "\" target=\"_blank\">" + .PrimaryURL + "</a></p>" +
        "<div class=\"code-block\">" + (.Message | gsub("\n"; "<br>")) + "</div>" +
        "</div>"' "$json_file" >> "$html_file"

    # Pied de page
    cat <<EOF >> "$html_file"
</body>
</html>
EOF
}

# Fonction principale
main() {
    check_trivy
    
    echo -e "${YELLOW}Lancement du scan Trivy dans: $SCAN_DIR${NC}"
    
    TEMP_JSON=$(mktemp)
    
    if ! trivy config --severity CRITICAL,HIGH,MEDIUM,LOW --format json --output "$TEMP_JSON" "$SCAN_DIR"; then
        echo -e "${RED}Erreur pendant le scan Trivy${NC}"
        rm -f "$TEMP_JSON"
        exit 1
    fi
    
    if [ ! -s "$TEMP_JSON" ]; then
        echo -e "${GREEN}Aucun problème détecté${NC}"
        rm -f "$TEMP_JSON"
        exit 0
    fi
    
    echo -e "${GREEN}Génération du rapport HTML...${NC}"
    generate_report "$TEMP_JSON" "$OUTPUT_FILE"
    rm -f "$TEMP_JSON"
    
    echo -e "${GREEN}Rapport généré: ${YELLOW}$OUTPUT_FILE${NC}"
}

main
