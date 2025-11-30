"""
Gestionnaire de règles iptables
Exécute les commandes système pour appliquer les configurations de pare-feu
"""
import subprocess
import logging
from typing import Tuple, List
from common.models import Firewall, IptablesRule


class IptablesManager:
    """
    Classe pour gérer les opérations iptables sur le système
    """

    def __init__(self, dry_run: bool = False):
        """
        Initialise le gestionnaire iptables

        Args:
            dry_run: Si True, affiche les commandes sans les exécuter (mode test)
        """
        self.dry_run = dry_run
        self.logger = logging.getLogger(__name__)

    def execute_command(self, command: str) -> Tuple[bool, str]:
        """
        Exécute une commande système

        Args:
            command: Commande à exécuter

        Returns:
            Tuple (success, message)
        """
        if self.dry_run:
            self.logger.info(f"[DRY-RUN] {command}")
            return True, f"Dry-run: {command}"

        try:
            # Exécuter la commande
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )

            if result.returncode == 0:
                self.logger.info(f"Command executed successfully: {command}")
                output = result.stdout.strip() if result.stdout else "Command executed"
                return True, output
            else:
                error_msg = result.stderr.strip() if result.stderr else f"Command failed with code {result.returncode}"
                self.logger.error(f"Command failed: {command} - {error_msg}")
                return False, error_msg

        except subprocess.TimeoutExpired:
            error_msg = f"Command timeout: {command}"
            self.logger.error(error_msg)
            return False, error_msg
        except FileNotFoundError:
            error_msg = "iptables command not found. Please install iptables."
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error executing command: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg

    def flush_all(self, table: str = "filter") -> Tuple[bool, str]:
        """
        Vide toutes les règles d'une table iptables

        Args:
            table: Nom de la table (filter, nat, mangle, raw)

        Returns:
            Tuple (success, message)
        """
        commands = [
            f"iptables -t {table} -F",      # Flush all chains
            f"iptables -t {table} -X",      # Delete all user-defined chains
            f"iptables -t {table} -Z"       # Zero all counters
        ]

        for cmd in commands:
            success, msg = self.execute_command(cmd)
            if not success:
                return False, f"Failed to flush table {table}: {msg}"

        # Réinitialiser les politiques par défaut à ACCEPT
        if table == "filter":
            for chain in ["INPUT", "OUTPUT", "FORWARD"]:
                success, msg = self.execute_command(f"iptables -t {table} -P {chain} ACCEPT")
                if not success:
                    return False, f"Failed to set default policy for {chain}: {msg}"

        return True, f"Table {table} flushed successfully"

    def flush_chain(self, table: str, chain: str) -> Tuple[bool, str]:
        """
        Vide une chaîne spécifique

        Args:
            table: Nom de la table
            chain: Nom de la chaîne (INPUT, OUTPUT, FORWARD, etc.)

        Returns:
            Tuple (success, message)
        """
        cmd = f"iptables -t {table} -F {chain}"
        success, msg = self.execute_command(cmd)

        if success:
            return True, f"Chain {chain} in table {table} flushed"
        else:
            return False, f"Failed to flush chain {chain}: {msg}"

    def set_default_policy(self, table: str, chain: str, policy: str) -> Tuple[bool, str]:
        """
        Définit la politique par défaut d'une chaîne

        Args:
            table: Nom de la table
            chain: Nom de la chaîne (INPUT, OUTPUT, FORWARD)
            policy: Politique (ACCEPT, DROP, REJECT)

        Returns:
            Tuple (success, message)
        """
        if policy not in ["ACCEPT", "DROP", "REJECT"]:
            return False, f"Invalid policy: {policy}. Must be ACCEPT, DROP, or REJECT"

        cmd = f"iptables -t {table} -P {chain} {policy}"
        success, msg = self.execute_command(cmd)

        if success:
            return True, f"Default policy for {chain} set to {policy}"
        else:
            return False, f"Failed to set policy: {msg}"

    def apply_rule(self, rule: IptablesRule, table: str = "filter", action: str = "A") -> Tuple[bool, str]:
        """
        Applique une règle iptables

        Args:
            rule: Objet IptablesRule contenant la règle
            table: Table iptables (filter, nat, etc.)
            action: Action iptables (A=append, I=insert, D=delete)

        Returns:
            Tuple (success, message)
        """
        cmd = rule.to_iptables_command(table, action)
        return self.execute_command(cmd)

    def apply_rules(self, rules: List[IptablesRule], table: str = "filter") -> Tuple[bool, str]:
        """
        Applique une liste de règles

        Args:
            rules: Liste d'objets IptablesRule
            table: Table iptables

        Returns:
            Tuple (success, message)
        """
        failed_rules = []

        for i, rule in enumerate(rules):
            success, msg = self.apply_rule(rule, table, "A")
            if not success:
                failed_rules.append(f"Rule {i+1}: {msg}")

        if failed_rules:
            error_msg = "Failed to apply some rules:\n" + "\n".join(failed_rules)
            return False, error_msg

        return True, f"Successfully applied {len(rules)} rules to table {table}"

    def load_firewall_config(self, firewall: Firewall) -> Tuple[bool, str]:
        """
        Charge la configuration complète d'un pare-feu

        Args:
            firewall: Objet Firewall contenant toutes les règles

        Returns:
            Tuple (success, message)
        """
        self.logger.info(f"Loading firewall configuration: {firewall.name}")

        # Liste des messages pour le résultat final
        messages = []
        has_errors = False

        # Parcourir toutes les tables du pare-feu
        for table_name, chains in firewall.tables.items():
            # Flusher la table avant d'appliquer les nouvelles règles
            success, msg = self.flush_all(table_name)
            if not success:
                messages.append(f"Warning: Could not flush table {table_name}: {msg}")
                has_errors = True
                # On continue quand même pour essayer d'appliquer les règles

            # Appliquer les règles pour chaque chaîne
            for chain_name, rules in chains.items():
                if not rules:
                    continue  # Ignorer les chaînes vides

                self.logger.info(f"Applying {len(rules)} rules to {table_name}/{chain_name}")

                for i, rule in enumerate(rules):
                    success, msg = self.apply_rule(rule, table_name, "A")
                    if not success:
                        error_msg = f"Failed to apply rule {i+1} in {table_name}/{chain_name}: {msg}"
                        self.logger.error(error_msg)
                        messages.append(error_msg)
                        has_errors = True
                    else:
                        self.logger.debug(f"Applied rule {i+1} in {table_name}/{chain_name}")

        # Résultat final
        if has_errors:
            full_msg = f"Firewall {firewall.name} loaded with errors:\n" + "\n".join(messages)
            return False, full_msg
        else:
            return True, f"Firewall {firewall.name} loaded successfully"

    def check_iptables_available(self) -> bool:
        """
        Vérifie si iptables est disponible sur le système

        Returns:
            True si iptables est disponible, False sinon
        """
        success, _ = self.execute_command("iptables --version")
        return success

    def list_rules(self, table: str = "filter") -> Tuple[bool, str]:
        """
        Liste toutes les règles d'une table

        Args:
            table: Nom de la table

        Returns:
            Tuple (success, output)
        """
        cmd = f"iptables -t {table} -L -n -v"
        return self.execute_command(cmd)

    def save_rules(self, filepath: str = "/etc/iptables/rules.v4") -> Tuple[bool, str]:
        """
        Sauvegarde les règles iptables actuelles dans un fichier

        Args:
            filepath: Chemin du fichier de sauvegarde

        Returns:
            Tuple (success, message)
        """
        cmd = f"iptables-save > {filepath}"
        # Utiliser shell=True pour la redirection
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )

            if result.returncode == 0:
                return True, f"Rules saved to {filepath}"
            else:
                return False, result.stderr.strip() if result.stderr else "Save failed"
        except Exception as e:
            return False, f"Error saving rules: {str(e)}"

    def restore_rules(self, filepath: str = "/etc/iptables/rules.v4") -> Tuple[bool, str]:
        """
        Restaure les règles iptables depuis un fichier

        Args:
            filepath: Chemin du fichier de sauvegarde

        Returns:
            Tuple (success, message)
        """
        cmd = f"iptables-restore < {filepath}"
        # Utiliser shell=True pour la redirection
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )

            if result.returncode == 0:
                return True, f"Rules restored from {filepath}"
            else:
                return False, result.stderr.strip() if result.stderr else "Restore failed"
        except Exception as e:
            return False, f"Error restoring rules: {str(e)}"
