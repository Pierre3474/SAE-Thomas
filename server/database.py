"""
Module de gestion de la base de données JSON
Gère les utilisateurs et les pare-feux
"""
import json
import hashlib
import os
from pathlib import Path
from typing import List, Optional
from common.models import User, Firewall, UserRole, FirewallStatus


class Database:
    """
    Gestionnaire de base de données basée sur des fichiers JSON
    """

    def __init__(self, data_dir: str = "data"):
        """
        Initialise la base de données

        Args:
            data_dir: Répertoire contenant les fichiers JSON
        """
        self.data_dir = Path(data_dir)
        self.users_file = self.data_dir / "users.json"
        self.firewalls_file = self.data_dir / "firewalls.json"

        # Créer le répertoire s'il n'existe pas
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Initialiser les fichiers si nécessaire
        self._init_files()

    def _init_files(self):
        """Initialise les fichiers JSON s'ils n'existent pas"""
        # Initialiser users.json avec un admin par défaut
        if not self.users_file.exists() or self.users_file.stat().st_size == 0:
            default_users = [
                User(
                    username="admin",
                    password_hash=self._hash_password("admin"),
                    role=UserRole.ADMIN,
                    enabled=True,
                    firewalls=[]
                )
            ]
            self._save_users(default_users)

        # Initialiser firewalls.json
        if not self.firewalls_file.exists() or self.firewalls_file.stat().st_size == 0:
            self._save_firewalls([])

    def _hash_password(self, password: str) -> str:
        """
        Hash un mot de passe avec SHA256

        Args:
            password: Mot de passe en clair

        Returns:
            Hash hexadécimal du mot de passe
        """
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def _save_users(self, users: List[User]):
        """Sauvegarde la liste des utilisateurs"""
        with open(self.users_file, 'w') as f:
            json.dump(
                [u.to_dict() for u in users],
                f,
                indent=2,
                ensure_ascii=False
            )

    def _save_firewalls(self, firewalls: List[Firewall]):
        """Sauvegarde la liste des pare-feux"""
        with open(self.firewalls_file, 'w') as f:
            json.dump(
                [fw.to_dict() for fw in firewalls],
                f,
                indent=2,
                ensure_ascii=False
            )

    def load_users(self) -> List[User]:
        """
        Charge tous les utilisateurs

        Returns:
            Liste des utilisateurs
        """
        try:
            with open(self.users_file, 'r') as f:
                data = json.load(f)
                return [User.from_dict(u) for u in data]
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def load_firewalls(self) -> List[Firewall]:
        """
        Charge tous les pare-feux

        Returns:
            Liste des pare-feux
        """
        try:
            with open(self.firewalls_file, 'r') as f:
                data = json.load(f)
                return [Firewall.from_dict(fw) for fw in data]
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """
        Authentifie un utilisateur

        Args:
            username: Nom d'utilisateur
            password: Mot de passe en clair

        Returns:
            User si authentification réussie, None sinon
        """
        users = self.load_users()
        password_hash = self._hash_password(password)

        for user in users:
            if user.username == username and user.password_hash == password_hash and user.enabled:
                return user

        return None

    def get_user(self, username: str) -> Optional[User]:
        """
        Récupère un utilisateur par son nom

        Args:
            username: Nom d'utilisateur

        Returns:
            User si trouvé, None sinon
        """
        users = self.load_users()
        for user in users:
            if user.username == username:
                return user
        return None

    def create_user(self, username: str, password: str, role: UserRole = UserRole.EDITOR) -> User:
        """
        Crée un nouvel utilisateur

        Args:
            username: Nom d'utilisateur
            password: Mot de passe en clair
            role: Rôle de l'utilisateur

        Returns:
            L'utilisateur créé

        Raises:
            ValueError: Si l'utilisateur existe déjà
        """
        users = self.load_users()

        # Vérifier si l'utilisateur existe déjà
        if any(u.username == username for u in users):
            raise ValueError(f"User {username} already exists")

        # Créer le nouvel utilisateur
        new_user = User(
            username=username,
            password_hash=self._hash_password(password),
            role=role,
            enabled=True,
            firewalls=[]
        )

        users.append(new_user)
        self._save_users(users)

        return new_user

    def update_user(self, username: str, **kwargs) -> User:
        """
        Met à jour un utilisateur

        Args:
            username: Nom d'utilisateur
            **kwargs: Attributs à mettre à jour (enabled, firewalls, etc.)

        Returns:
            L'utilisateur mis à jour

        Raises:
            ValueError: Si l'utilisateur n'existe pas
        """
        users = self.load_users()
        user = None

        for u in users:
            if u.username == username:
                user = u
                break

        if not user:
            raise ValueError(f"User {username} not found")

        # Mettre à jour les attributs
        if 'enabled' in kwargs:
            user.enabled = kwargs['enabled']
        if 'firewalls' in kwargs:
            user.firewalls = kwargs['firewalls']
        if 'role' in kwargs:
            user.role = kwargs['role']
        if 'password' in kwargs:
            user.password_hash = self._hash_password(kwargs['password'])

        self._save_users(users)
        return user

    def delete_user(self, username: str):
        """
        Supprime un utilisateur

        Args:
            username: Nom d'utilisateur
        """
        users = self.load_users()
        users = [u for u in users if u.username != username]
        self._save_users(users)

    def get_firewall(self, name: str) -> Optional[Firewall]:
        """
        Récupère un pare-feu par son nom

        Args:
            name: Nom du pare-feu

        Returns:
            Firewall si trouvé, None sinon
        """
        firewalls = self.load_firewalls()
        for fw in firewalls:
            if fw.name == name:
                return fw
        return None

    def create_firewall(self, name: str) -> Firewall:
        """
        Crée un nouveau pare-feu

        Args:
            name: Nom du pare-feu

        Returns:
            Le pare-feu créé

        Raises:
            ValueError: Si le pare-feu existe déjà
        """
        firewalls = self.load_firewalls()

        # Vérifier si le pare-feu existe déjà
        if any(fw.name == name for fw in firewalls):
            raise ValueError(f"Firewall {name} already exists")

        # Créer le nouveau pare-feu
        new_firewall = Firewall(name=name)
        firewalls.append(new_firewall)
        self._save_firewalls(firewalls)

        return new_firewall

    def update_firewall(self, firewall: Firewall):
        """
        Met à jour un pare-feu

        Args:
            firewall: Objet Firewall mis à jour
        """
        firewalls = self.load_firewalls()

        # Remplacer le pare-feu existant
        for i, fw in enumerate(firewalls):
            if fw.name == firewall.name:
                firewalls[i] = firewall
                break

        self._save_firewalls(firewalls)

    def delete_firewall(self, name: str):
        """
        Supprime un pare-feu

        Args:
            name: Nom du pare-feu
        """
        firewalls = self.load_firewalls()
        firewalls = [fw for fw in firewalls if fw.name != name]
        self._save_firewalls(firewalls)
