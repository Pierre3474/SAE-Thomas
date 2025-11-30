"""
SystÃ¨me de journalisation des Ã©vÃ©nements
Enregistre toutes les actions importantes dans des fichiers horodatÃ©s
"""
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from common.models import LogEntry


class Logger:
    """
    Gestionnaire de logs pour le serveur
    """

    def __init__(self, log_dir: str = "data/logs"):
        """
        Initialise le logger

        Args:
            log_dir: RÃ©pertoire de stockage des logs
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Nom du fichier de log actuel (par jour)
        self.current_log_file = self._get_log_filename()

    def _get_log_filename(self) -> Path:
        """
        GÃ©nÃ¨re le nom du fichier de log pour aujourd'hui

        Returns:
            Chemin du fichier de log
        """
        today = datetime.now().strftime("%Y-%m-%d")
        return self.log_dir / f"firewall_{today}.log"

    def _write_log(self, entry: LogEntry):
        """
        Ãcrit une entrÃ©e de log dans le fichier

        Args:
            entry: EntrÃ©e de log Ã  Ã©crire
        """
        # VÃ©rifier si on doit changer de fichier (nouveau jour)
        current_file = self._get_log_filename()
        if current_file != self.current_log_file:
            self.current_log_file = current_file

        # Ãcrire dans le fichier
        with open(self.current_log_file, 'a', encoding='utf-8') as f:
            f.write(entry.to_string() + "\n")

        # Afficher aussi dans la console pour le debug
        print(entry.to_string())

    def info(self, username: str, message: str, firewall: Optional[str] = None):
        """
        Enregistre une information

        Args:
            username: Nom d'utilisateur
            message: Message Ã  enregistrer
            firewall: Nom du pare-feu concernÃ© (optionnel)
        """
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level="INFO",
            username=username,
            message=message,
            firewall=firewall
        )
        self._write_log(entry)

    def error(self, username: str, message: str, firewall: Optional[str] = None):
        """
        Enregistre une erreur

        Args:
            username: Nom d'utilisateur
            message: Message d'erreur
            firewall: Nom du pare-feu concernÃ© (optionnel)
        """
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level="ERROR",
            username=username,
            message=message,
            firewall=firewall
        )
        self._write_log(entry)

    def warning(self, username: str, message: str, firewall: Optional[str] = None):
        """
        Enregistre un avertissement

        Args:
            username: Nom d'utilisateur
            message: Message d'avertissement
            firewall: Nom du pare-feu concernÃ© (optionnel)
        """
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level="WARNING",
            username=username,
            message=message,
            firewall=firewall
        )
        self._write_log(entry)

    def command(self, username: str, command: str, firewall: Optional[str] = None):
        """
        Enregistre une commande exÃ©cutÃ©e

        Args:
            username: Nom d'utilisateur
            command: Commande exÃ©cutÃ©e
            firewall: Nom du pare-feu concernÃ© (optionnel)
        """
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level="CMD",
            username=username,
            message=command,
            firewall=firewall
        )
        self._write_log(entry)

    def auth_success(self, username: str, ip: str):
        """
        Enregistre une authentification rÃ©ussie

        Args:
            username: Nom d'utilisateur
            ip: Adresse IP du client
        """
        self.info(username, f"Authentication successful from {ip}")

    def auth_failed(self, username: str, ip: str):
        """
        Enregistre une tentative d'authentification Ã©chouÃ©e

        Args:
            username: Nom d'utilisateur
            ip: Adresse IP du client
        """
        self.warning(username, f"Authentication failed from {ip}")

    def get_recent_logs(self, n: int = 50) -> list:
        """
        RÃ©cupÃ¨re les N derniÃ¨res entrÃ©es de log

        Args:
            n: Nombre d'entrÃ©es Ã  rÃ©cupÃ©rer

        Returns:
            Liste des N derniÃ¨res lignes de log
        """
        try:
            with open(self.current_log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                return lines[-n:] if len(lines) > n else lines
        except FileNotFoundError:
            return []


# Instance singleton du logger
_logger_instance = None


def get_logger() -> Logger:
    """
    RÃ©cupÃ¨re l'instance singleton du logger

    Returns:
        Instance du logger
    """
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = Logger()
    return _logger_instance
