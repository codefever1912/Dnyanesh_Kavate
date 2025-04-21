#!/usr/bin/env python3
"""
Sensitive Path Discovery Module for Attack Surface Monitoring Tool
This module discovers sensitive paths and directories on web servers.
"""

import requests
import sys
import json
import time
from typing import Dict, Any, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class PathDiscovery:
    """
    A class to discover sensitive paths and directories on web servers.
    """

    def __init__(self, target: str, max_threads: int = 10, timeout: int = 5, 
                 delay: float = 0.1, wordlist_size: str = "medium"):
        """
        Initialize the PathDiscovery with the target URL.

        Args:
            target (str): The target URL to scan.
            max_threads (int): Maximum number of threads for concurrent operations.
            timeout (int): Timeout in seconds for HTTP requests.
            delay (float): Delay between requests in seconds.
            wordlist_size (str): Size of wordlist to use ("small", "medium", "large").
        """
        self.target = target
        self.max_threads = max_threads
        self.timeout = timeout
        self.delay = delay
        self.wordlist_size = wordlist_size
        self.discovered_paths: List[Dict[str, Any]] = []
        
        # Common sensitive paths to check
        self.small_wordlist = [
            "admin", "login", "wp-admin", "administrator", "phpmyadmin", "dashboard",
            "wp-content", "backup", "backups", "data", "db", "database", "mysql",
            "config", "configuration", "setup", "install", "uploads", "tmp", "temp",
            "api", "admin.php", "login.php", "wp-login.php", "user", "users", "account",
            "accounts", "home", "log", "logs", "robots.txt", ".git", ".svn", ".env",
            "server-status", "test", "dev", "development", "staging", "prod", "production",
            "phpinfo.php", "info.php", ".htaccess", "console", "wp-config.php", ".DS_Store"
        ]
        
        self.medium_wordlist = self.small_wordlist + [
            "admin-console", "adminer", "administrator.php", "wp-admin.php", "cpanel",
            "webmail", "mail", "email", "smtp", "webdav", "secure", "security", "auth",
            "authentication", "login-redirect", "portal", "admin-portal", "cms", "joomla",
            "drupal", "wordpress", "wp", "laravel", "symfony", "rails", "django", "flask",
            "node", "nodejs", "react", "angular", "vue", "php", "asp", "aspx", "jsp",
            "cgi-bin", "bin", "js", "javascript", "css", "images", "img", "static", "assets",
            "media", "download", "downloads", "upload", "uploads", "file", "files", "document",
            "documents", "pdf", "docs", "documentation", "doc", "api-docs", "swagger", "graphql",
            "soap", "wsdl", "xml", "json", "rss", "atom", "feed", "sitemap", "sitemap.xml",
            "backup.zip", "backup.sql", "backup.tar.gz", "backup.tgz", "dump.sql", "1.sql",
            "database.sql", "db.sql", "site.sql", "mysql.sql", "mysqldump.sql", "postgres.sql",
            "postgresql.sql", "backup.bak", "backup.old", "old", "new", "dev.php", "phpinfo",
            "test.php", "info", "server-info", "status", "stats", "statistics", "monitoring",
            "monitor", "health", "check", "ping", "trace", "tracert", "debug", "error", "errors",
            "admin/login", "admin/dashboard", "admin/index", "admin/admin", "admin/config",
            "wp-content/uploads", "wp-content/plugins", "wp-content/themes", "wp-includes"
        ]
        
        # For large wordlist, we would typically use a file, but for simplicity
        # we'll just add more entries to the medium wordlist
        self.large_wordlist = self.medium_wordlist + [
            "system", "sys", "root", "admin/backup", "admin/db", "admin/logs", "admin/files",
            "admin/upload", "admin/users", "admin/settings", "admin/configuration", "admin/config",
            "admin/database", "admin/dump", "admin/phpinfo", "admin/info", "admin/phpinfo.php",
            "admin/test", "admin/dev", "admin/staging", "admin/prod", "admin/production",
            "admin/development", "admin/console", "admin/shell", "admin/cmd", "admin/command",
            "admin/terminal", "admin/ssh", "admin/ftp", "admin/sftp", "admin/scp", "admin/rsync",
            "config.php", "configuration.php", "settings.php", "setup.php", "install.php",
            "installed.php", "upgrade.php", "update.php", "backup.php", "restore.php",
            "db.php", "database.php", "sql.php", "mysql.php", "mysqli.php", "pgsql.php",
            "postgres.php", "postgresql.php", "oracle.php", "sqlite.php", "mongodb.php",
            "mongo.php", "redis.php", "memcached.php", "cache.php", "session.php", "tmp.php",
            "temp.php", "upload.php", "uploaded.php", "file.php", "files.php", "download.php",
            "downloads.php", "media.php", "image.php", "images.php", "img.php", "picture.php",
            "pictures.php", "photo.php", "photos.php", "pic.php", "pics.php", "gallery.php",
            "galleries.php", "video.php", "videos.php", "audio.php", "music.php", "mp3.php",
            "mp4.php", "movie.php", "movies.php", "admin.asp", "admin.aspx", "admin.jsp",
            "admin.cgi", "admin.pl", "admin.py", "login.asp", "login.aspx", "login.jsp",
            "login.cgi", "login.pl", "login.py", "logon.php", "logon.asp", "logon.aspx",
            "logon.jsp", "logon.cgi", "logon.pl", "logon.py", "signin.php", "signin.asp",
            "signin.aspx", "signin.jsp", "signin.cgi", "signin.pl", "signin.py", "signup.php",
            "register.php", "registration.php", "activate.php", "forgot.php", "reset.php",
            "passwd.php", "password.php", "recover.php", "recovery.php", "unlock.php",
            "verify.php", "verification.php", "validate.php", "validation.php", "confirm.php",
            "confirmation.php", "approved.php", "approval.php", "authenticate.php",
            "authentication.php", "oauth.php", "oauth2.php", "openid.php", "saml.php",
            "ldap.php", "ad.php", "activedirectory.php", "sso.php", "logout.php", "signout.php"
        ]

    def discover(self) -> Dict[str, Any]:
        """
        Discover sensitive paths on the target.

        Returns:
            Dict[str, Any]: A dictionary containing discovered paths.
        """
        print(f"[+] Starting sensitive path discovery on {self.target}")
        
        # Make sure the target has a scheme
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'https://' + self.target
            # Try HTTPS first, fallback to HTTP if needed
            try:
                self._test_connection(self.target)
            except:
                self.target = 'http://' + self.target.replace('https://', '')
                self._test_connection(self.target)
        
        # Normalize target URL to ensure it ends with a slash
        if not self.target.endswith('/'):
            self.target += '/'
        
        # Select wordlist based on size
        if self.wordlist_size == "small":
            wordlist = self.small_wordlist
        elif self.wordlist_size == "large":
            wordlist = self.large_wordlist
        else:
            wordlist = self.medium_wordlist
        
        print(f"[+] Using {self.wordlist_size} wordlist with {len(wordlist)} paths")
        
        # Discover paths using threading
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_path = {executor.submit(self._check_path, path): path for path in wordlist}
            
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        self.discovered_paths.append(result)
                        print(f"[+] Discovered: {result['url']} - Status: {result['status_code']}")
                except Exception as e:
                    print(f"[!] Error checking {path}: {e}", file=sys.stderr)
        
        # Sort discovered paths by status code
        self.discovered_paths.sort(key=lambda x: x['status_code'])
        
        # Prepare the result
        result = {
            "target": self.target,
            "total_paths_checked": len(wordlist),
            "discovered_paths": self.discovered_paths,
            "sensitive_paths_count": len(self.discovered_paths)
        }
        
        print(f"[+] Path discovery complete: found {len(self.discovered_paths)} sensitive paths")
        
        return result

    def _test_connection(self, url: str) -> bool:
        """
        Test connection to the target URL.

        Args:
            url (str): The URL to test.

        Returns:
            bool: True if connection successful, False otherwise.
        """
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            )
            return response.status_code < 400
        except:
            return False

    def _check_path(self, path: str) -> Dict[str, Any]:
        """
        Check if a path exists on the target.

        Args:
            path (str): The path to check.

        Returns:
            Dict[str, Any]: A dictionary containing information about the path if it exists, None otherwise.
        """
        url = self.target + path
        
        try:
            # Add delay to avoid overwhelming the server
            time.sleep(self.delay)
            
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,  # Don't follow redirects to get accurate status codes
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            )
            
            # Check if the path exists (status codes 200-299, 301, 302, 307, 308)
            if response.status_code < 400:
                # Extract the title if it's HTML
                title = "Unknown"
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' in content_type and len(response.text) > 0:
                    try:
                        title_start = response.text.find('<title>')
                        title_end = response.text.find('</title>')
                        if title_start != -1 and title_end != -1:
                            title = response.text[title_start + 7:title_end].strip()
                    except:
                        pass
                
                # Determine sensitivity level based on path and status code
                sensitivity = "low"
                if any(keyword in path.lower() for keyword in ['admin', 'login', 'config', 'backup', 'db', 'sql', 'password']):
                    sensitivity = "high"
                elif any(keyword in path.lower() for keyword in ['user', 'account', 'dashboard', 'api', 'console', 'log']):
                    sensitivity = "medium"
                
                # Adjust sensitivity based on status code
                if response.status_code == 200:
                    # 200 OK is more sensitive
                    if sensitivity == "low":
                        sensitivity = "medium"
                
                return {
                    "path": path,
                    "url": url,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "title": title,
                    "content_length": len(response.content),
                    "sensitivity": sensitivity
                }
        
        except Exception as e:
            # print(f"[!] Error checking {path}: {e}", file=sys.stderr)
            pass
        
        return None


def discover_paths(target: str, wordlist_size: str = "medium") -> Dict[str, Any]:
    """
    Convenience function to discover sensitive paths on a target.

    Args:
        target (str): The target URL to scan.
        wordlist_size (str): Size of wordlist to use ("small", "medium", "large").

    Returns:
        Dict[str, Any]: A dictionary containing discovered paths.
    """
    discoverer = PathDiscovery(target, wordlist_size=wordlist_size)
    return discoverer.discover()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        wordlist_size = sys.argv[2] if len(sys.argv) > 2 else "medium"
        
        try:
            result = discover_paths(target_url, wordlist_size)
            print(f"\nSensitive path discovery results for {target_url}:")
            print(f"Total paths checked: {result['total_paths_checked']}")
            print(f"Discovered sensitive paths: {result['sensitive_paths_count']}")
            
            if result['discovered_paths']:
                print("\nTop findings:")
                for path in result['discovered_paths'][:10]:  # Show top 10
                    print(f"  {path['url']} - Status: {path['status_code']} - Sensitivity: {path['sensitivity']}")
                
                if len(result['discovered_paths']) > 10:
                    print(f"  ... and {len(result['discovered_paths']) - 10} more")
            else:
                print("No sensitive paths discovered.")
        
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python path_discovery.py <target_url> [wordlist_size]", file=sys.stderr)
