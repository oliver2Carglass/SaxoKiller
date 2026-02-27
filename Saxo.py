import json
import os
import base64
import http.server
import socketserver
import urllib.parse as urlparse
import webbrowser
import requests
import secrets
import time
import pandas as pd
import datetime


class SaxoClient:
    AUTH_BASE_LIVE = "https://live.logonvalidation.net"
    AUTH_URL_LIVE  = f"{AUTH_BASE_LIVE}/authorize"
    TOKEN_URL_LIVE = f"{AUTH_BASE_LIVE}/token"
    API_BASE_LIVE  = "https://gateway.saxobank.com/openapi"

    def __init__(self, app_key, app_secret, app_name,
                 redirect_uri="http://127.0.0.1:8001/callback",
                 app_id=None, bind_all=False, wait_timeout=180):
        self._app_key = app_key
        self._app_secret = app_secret
        self._app_name = app_name
        self._app_id = app_id
        self._redirect_uri = redirect_uri
        self._bind_all = bind_all         # <-- utile WSL2/Docker
        self._wait_timeout = wait_timeout # <-- 3 min
        self._access_token = None
        self._refresh_token = None
        self._session = requests.Session()
        self._expected_state = None


        #a enlever après 
        self.token_url = "https://token-saxo-powerbi-hvdfhtabfudwgkdu.francecentral-01.azurewebsites.net/api/saxo_access_token" # token maxence
        self.access_token1 = None



    def get_accounts(self):
        url = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
        r = self._session.get(url, timeout=30)
        r.raise_for_status()
        return r.json().get("Data", [])
  
  

    class OAuthCallbackHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse.urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404); self.end_headers()
                self.wfile.write(b"Not Found")
                return
            qs = urlparse.parse_qs(parsed.query)
            code = qs.get("code", [None])[0]
            state = qs.get("state", [None])[0]

            # stocke pour le serveur
            self.server.code = code
            self.server.state = state

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK - You may close this window.")

    def _extract_host_port(self):
        parsed = urlparse.urlparse(self._redirect_uri)
        host = parsed.hostname or "127.0.0.1"
        port = int(parsed.port or 80)
        return host, port

    def _wait_for_code(self):
        host, port = self._extract_host_port()
        # bind sur 0.0.0.0 si demandé (WSL2/Docker)
        bind_host = "0.0.0.0" if self._bind_all else host
        start = time.time()
        with socketserver.TCPServer((bind_host, port), self.OAuthCallbackHandler) as httpd:
            httpd.code = None
            httpd.state = None
            while httpd.code is None:
                if time.time() - start > self._wait_timeout:
                    raise TimeoutError(f"Callback non reçu dans {self._wait_timeout}s")
                httpd.handle_request()
            return httpd.code, httpd.state

    def login_live_code(self):
        self._expected_state = secrets.token_urlsafe(24)

        params = {
            "response_type": "code",
            "client_id": self._app_key,
            "redirect_uri": self._redirect_uri,
            "state": self._expected_state
        }
        auth_url = self.AUTH_URL_LIVE + "?" + urlparse.urlencode(params)

        print("\n➡️ Ouvre ton navigateur et connecte-toi (LIVE):")
        print(auth_url)
        webbrowser.open(auth_url)

        print(f"\n⏳ En attente du code sur {self._redirect_uri} ...")
        code, state = self._wait_for_code()
        if state != self._expected_state:
            raise RuntimeError(f"State inattendu. Attendu={self._expected_state}, reçu={state}")
        print("✔ Code OAuth reçu :", code)

        basic_auth = base64.b64encode(f"{self._app_key}:{self._app_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {basic_auth}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri
        }
        r = requests.post(self.TOKEN_URL_LIVE, headers=headers, data=data, timeout=30)
        r.raise_for_status()
        token = r.json()

        self._access_token = token["access_token"]
        self._refresh_token = token.get("refresh_token")

        self._session.headers.update({
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
        print("\n🎉 TOKEN LIVE OBTENU !")






# GET DATA WITH MARKET !!
    def get_cash(self):
        """
        Retourne UNIQUEMENT les liquidités disponibles (= CashAvailableForTrading).
        C’est la vraie valeur des liquidités utilisables.
        """

        if not self._access_token:
            raise RuntimeError("Pas de token – appelle login_live_code() d'abord.")

        # 1) Récupérer AccountKey + ClientKey
        url_acc = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
        r = self._session.get(url_acc, timeout=30)
        r.raise_for_status()
        accs = (r.json() or {}).get("Data", []) or []

        if not accs:
            raise RuntimeError("Aucun compte trouvé via /accounts/me")

        # On prend le premier compte (ou selon ton besoin tu peux choisir)
        acc = accs[0]
        account_key = acc["AccountKey"]
        client_key = (
            acc.get("ClientKey")
            or acc.get("ClientId")
            or acc.get("ClientKeyId")
        )

        if not client_key:
            raise RuntimeError("ClientKey introuvable")

        # 2) Appel balances avec AccountKey + ClientKey (obligatoire)
        url_bal = f"{self.API_BASE_LIVE}/port/v1/balances"
        params = {"ClientKey": client_key, "AccountKey": account_key}

        rb = self._session.get(url_bal, params=params, timeout=30)
        rb.raise_for_status()
        data = rb.json() or {}

        # 3) Extraction du bon champ : CashAvailableForTrading
        def extract_liquidity(obj):
            if not obj:
                return 0.0

            # Le champ exact que tu veux :
            val = obj.get("CashAvailableForTrading")
            if isinstance(val, (int, float, str)) and val not in (None, ""):
                try:
                    return float(val)
                except:
                    pass

            # fallback si Saxo utilise CashBalance – NetPositionsValue
            for fallback_key in ["CashBalance"]:
                val = obj.get(fallback_key)
                if isinstance(val, (int, float, str)) and val not in (None, ""):
                    try:
                        return float(val)
                    except:
                        pass
            return 0.0

        # Plusieurs formats possibles
        if "Data" in data and isinstance(data["Data"], list) and data["Data"]:
            balance = data["Data"][0].get("Balance", {})
        else:
            balance = data.get("Balance", data)

        liquidity = extract_liquidity(balance)
        return round(liquidity, 2)

    def get_positions(self, account_key: str = None, client_key: str = None):
        """
        Retourne la liste des positions sous la forme :
        [
            {
                "name": "Microsoft Corp",
                "quantity": 12,
                "asset_type": "Stock",
                "uic": 19040
            },
            ...
        ]
        """

        if not self._access_token:
            raise RuntimeError("Pas de token – appelle login_live_code() d'abord.")

        # 1️⃣ Choix du compte si rien n'est fourni
        if not account_key or not client_key:
            # Récupération des comptes
            url_acc = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
            r = self._session.get(url_acc, timeout=30)
            r.raise_for_status()
            accs = (r.json() or {}).get("Data", []) or []

            if not accs:
                raise RuntimeError("Aucun compte trouvé via /accounts/me")

            # On prend le premier compte (tu peux ajuster)
            acc = accs[0]
            account_key = acc["AccountKey"]
            client_key = (
                acc.get("ClientKey") or 
                acc.get("ClientId") or 
                acc.get("ClientKeyId")
            )

        # 2️⃣ Appel des positions AVEC FieldGroups (comme ton script PowerBI)
        url_pos = f"{self.API_BASE_LIVE}/port/v1/netpositions"
        params = {
            "AccountKey": account_key,
            "ClientKey": client_key,
            "FieldGroups": "DisplayAndFormat,NetPositionBase,NetPositionView"
        }

        rp = self._session.get(url_pos, params=params, timeout=30)
        rp.raise_for_status()
        items = (rp.json() or {}).get("Data", []) or []

        results = []

        for it in items:
            display = it.get("DisplayAndFormat", {}) or {}
            base    = it.get("NetPositionBase", {}) or {}
            instr   = it.get("Instrument", {}) or {}

            # Nom du produit : même logique que ton code PowerBI
            name = (
                display.get("Description")
                or instr.get("Description")
                or instr.get("Symbol")
                or f"{instr.get('AssetType','INCONNU')} {instr.get('Uic','')}".strip()
                or "INCONNU"
            )

            # Quantité
            try:
                qty = float(base.get("Amount") or 0)
            except:
                qty = 0.0

            # Type d'actif & UIC
            asset_type = instr.get("AssetType", "INCONNU")
            uic = instr.get("Uic")

            # On ne garde que les positions avec quantité ≠ 0
            if qty != 0:
                results.append({
                    "name": name,
                    "quantity": qty,
                    "asset_type": asset_type,
                    "uic": uic
                })

        return {
            "account_key_used": account_key,
            "client_key_used": client_key,
            "positions": results
        }


   
    def get_total(self):

        """
        Retourne le cash disponible (CashBalance) pour le compte principal Saxo.
        Nécessite : ClientKey et AccountKey.
        """
        if not self._access_token:
            raise RuntimeError("Pas de token – appelle login_live_code() d'abord.")

        # 1️⃣ Récupérer comptes pour obtenir ClientKey + AccountKey
        url_acc = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
        r = self._session.get(url_acc, timeout=30)
        r.raise_for_status()
        accs = (r.json() or {}).get("Data", []) or []

        if not accs:
            raise RuntimeError("Impossible de récupérer les comptes via /accounts/me")

        # Sélection du premier compte (ou celui qui a du cash)
        selected = None
        for a in accs:
            try:
                if float(a.get("CashBalance") or 0) != 0:
                    selected = a
                    break
            except:
                pass

        if not selected:
            selected = accs[0]

        account_key = selected["AccountKey"]
        client_key = (
            selected.get("ClientKey") or
            selected.get("ClientId") or
            selected.get("ClientKeyId")
        )

        if not client_key:
            raise RuntimeError("ClientKey introuvable dans les données du compte")

        # 2️⃣ Appel balances (doit obligatoirement inclure ClientKey + AccountKey)
        url_bal = f"{self.API_BASE_LIVE}/port/v1/balances"
        params = {
            "ClientKey": client_key,
            "AccountKey": account_key
        }

        rb = self._session.get(url_bal, params=params, timeout=30)
        rb.raise_for_status()
        data = rb.json() or {}

        # 3️⃣ Extraction du CashBalance selon le format retourné
        def extract_cash(obj):
            if not obj:
                return 0.0
            for key in ["CashBalance", "AvailableCash", "NetFreeMargin"]:
                val = obj.get(key)
                if isinstance(val, (int, float, str)) and val not in (None, ""):
                    try: return float(val)
                    except: pass
            return 0.0

        # Plusieurs formats possibles : { Balance:{...} } ou { Data:[{Balance:{...}}] }
        if "Data" in data:
            balance_obj = data["Data"][0].get("Balance", {})
        else:
            balance_obj = data.get("Balance", data)

        cash = extract_cash(balance_obj)
        return cash

    def info_needed_for_trading(self, ISIN: str):
        """
        Version fidèle au code original PowerBI :
        - Recherche instrument via Keywords (100% LIVE-compatible)
        - Fallback avec suffixe ISIN
        - Renvoie UIC + AssetType
        """

        if not self._access_token:
            raise RuntimeError("Pas de token – appelle login_live_code() d'abord.")

        search_url = f"{self.API_BASE_LIVE}/ref/v1/instruments"

        # ---- TEST 1 : ISIN complet ----
        params = {
            "Keywords": ISIN,
            "IncludeNonTradable": True
        }

        r = self._session.get(search_url, params=params, timeout=30)
        r.raise_for_status()
        res = r.json()

        items = res.get("Data", []) or []

        # ---- TEST 2 : Suffixe si rien trouvé ----
        if not items:
            suffixe = ISIN[-7:]
            params["Keywords"] = suffixe

            r2 = self._session.get(search_url, params=params, timeout=30)
            r2.raise_for_status()
            items = r2.json().get("Data", []) or []

        if not items:
            return None

        inst = items[0]

        return {
            "uic": inst.get("Identifier"),
            "type": inst.get("AssetType")
        }

    def get_product_details(self, uic, asset_type):
        """Récupère les détails techniques (TickSize, devise, etc.)"""
        url = f"{self.API_BASE_LIVE}/ref/v1/instruments/details"
        params = {"Uics": uic, "AssetTypes": asset_type}
        r = self._session.get(url, params=params)
        r.raise_for_status()
        data = r.json().get("Data", [])
        return data[0] if data else None

    def get_open_orders(self):
        """Liste les ordres en attente (Working Orders)"""
        url_acc = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
        acc = self._session.get(url_acc).json()['Data'][0]
        
        url = f"{self.API_BASE_LIVE}/port/v1/orders"
        params = {"AccountKey": acc["AccountKey"], "ClientKey": acc["ClientKey"]}
        r = self._session.get(url, params=params)
        r.raise_for_status()
        return r.json().get("Data", [])

    def order(self, SellBuy: str, isLimit: bool, Price: float = None, productInfo: dict = None, amount: float = None):

        """
        Version CORRIGÉE : Utilise la structure 'Arguments' si nécessaire et force le typage.
        """
        if not self._access_token:
            raise RuntimeError("Connectez-vous d'abord.")

        uic = productInfo.get("uic")
        asset_type = productInfo.get("type")

        # 1. Récupération AccountKey
        url_acc = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
        acc_data = self._session.get(url_acc).json()
        account_key = acc_data['Data'][0]["AccountKey"]

        # 2. Préparation du payload
        url_order = f"{self.API_BASE_LIVE}/trade/v2/orders"
        
        # Structure de base que Saxo attend pour les instruments complexes
        payload = {
            "AccountKey": account_key,
            "Amount": float(amount),
            "AssetType": asset_type,
            "BuySell": SellBuy,
            "OrderDuration": {"DurationType": "DayOrder"},
            "ManualOrder": True,
            "Uic": int(uic)
        }

        if isLimit:
            payload["OrderType"] = "Limit"
            payload["OrderPrice"] = float(Price) # <--- ESSENTIEL : Saxo demande parfois OrderPrice au lieu de Price
            payload["Price"] = float(Price)      # On met les deux pour être sûr
        else:
            payload["OrderType"] = "Market"

        # 3. Envoi
        r = self._session.post(url_order, json=payload, timeout=30)
        
        if not r.ok:
            print(f"DEBUG PAYLOAD: {payload}")
            print(f"🚨 ERREUR SAXO ({r.status_code}) : {r.json()}")
            r.raise_for_status()
            
        return r.json()
    
    def cancel_order(self, order_id):
        """
        Annule un ordre en cours via son OrderId.
        """
        if not self._access_token:
            raise RuntimeError("Pas de token.")

        # Récupération AccountKey (nécessaire pour l'URL)
        url_acc = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
        acc = self._session.get(url_acc).json()['Data'][0]
        account_key = acc["AccountKey"]

        url = f"{self.API_BASE_LIVE}/trade/v2/orders/{order_id}"
        params = {"AccountKey": account_key}
        
        r = self._session.delete(url, params=params, timeout=30)
        
        if r.status_code == 204:
            print(f"✅ Ordre {order_id} annulé avec succès.")
            return True
        else:
            print(f"❌ Erreur lors de l'annulation : {r.text}")
            return False

    def cancel_all_orders_for_uic(self, uic):

        """
        Cherche et annule tous les ordres en cours pour un produit spécifique.
        """
        orders = self.get_open_orders()
        cancelled_count = 0
        for o in orders:
            if o['Uic'] == uic:
                if self.cancel_order(o['OrderId']):
                    cancelled_count += 1
        return cancelled_count

    def diagnostic_turbo(self, uic):

        url = f"{self.API_BASE_LIVE}/trade/v1/infoprices"
        # On teste sans AssetType pour voir ce que le serveur suggère
        params = {'Uic': uic, 'AssetType': 'WarrantKnockOut', 'FieldGroups': 'Quote,PriceInfoDetails'}
        r = self._session.get(url, params=params)
        data = r.json()
        
        quote = data.get('Quote', {})
        print(f"--- DIAGNOSTIC UIC {uic} ---")
        print(f"PriceTypeAsk: {quote.get('PriceTypeAsk')}") # Doit être 'Firm' ou 'Indicative'
        print(f"ErrorCode: {quote.get('ErrorCode')}")
        print(f"PriceSource: {data.get('PriceSource')}")
        return data





# TEMPORARY : FONCTION DE RÉCUPÉRATION DES DONNÉES HISTORIQUES AVEC FORMATAGE PANDAS   
    def get_chart_data(self, uic, asset_type='FxSpot', horizon=1440, count=200, mode=None, time=None):
        """
        Récupère les données historiques pour un instrument
        
        Args:
            uic (int): Universal Instrument Code (ex: 21 pour EUR/USD)
            asset_type (str): Type d'actif (FxSpot, Stock, etc.)
            horizon (int): Intervalle en minutes (1, 5, 15, 60, 1440=daily, etc.)
            count (int): Nombre de barres à récupérer (max 1200)
            mode (str): 'From' ou 'UpTo' - si spécifié, time doit aussi être spécifié
            time (str): Date/heure ISO format (ex: '2026-02-13T00:00:00Z')
        
        Returns:
            pandas.DataFrame: DataFrame avec les données OHLC
        """
        endpoint = "https://gateway.saxobank.com/openapi/chart/v3/charts"
        
        params = {
            'Uic': uic,
            'AssetType': asset_type,
            'Horizon': horizon,
            'Count': count,
            'FieldGroups': 'Data'
        }
        
        # Ajouter Mode et Time seulement si les deux sont spécifiés
        if mode and time:
            params['Mode'] = mode
            params['Time'] = time
        
        try:
            response = requests.get(
                endpoint,
                headers=self._get_headers(),
                params=params
            )
            response.raise_for_status()
            data = response.json()
            
            # Extraction des informations
            chart_info = data.get('ChartInfo', {})
            display_info = data.get('DisplayAndFormat', {})
            samples = data.get('Data', [])
            
            # Création du DataFrame
            df = pd.DataFrame(samples)
            
            if not df.empty:
                # Conversion du temps en datetime
                df['Time'] = pd.to_datetime(df['Time'])
                df.set_index('Time', inplace=True)
                
                # Pour le Forex, créer des colonnes OHLC simplifiées (moyenne Bid/Ask)
                if 'OpenBid' in df.columns and 'OpenAsk' in df.columns:
                    df['Open'] = (df['OpenBid'] + df['OpenAsk']) / 2
                    df['High'] = (df['HighBid'] + df['HighAsk']) / 2
                    df['Low'] = (df['LowBid'] + df['LowAsk']) / 2
                    df['Close'] = (df['CloseBid'] + df['CloseAsk']) / 2
                
                # Affichage des informations
                print(f"✓ Données récupérées pour {display_info.get('Symbol', 'Instrument')}")
                print(f"  Description: {display_info.get('Description', 'N/A')}")
                print(f"  Devise: {display_info.get('Currency', 'N/A')}")
                print(f"  Décimales: {display_info.get('Decimals', 'N/A')}")
                print(f"  Délai: {chart_info.get('DelayedByMinutes', 0)} minutes")
                print(f"  Intervalle: {chart_info.get('Horizon', horizon)} minutes")
                print(f"  Nombre de barres: {len(df)}")
                print(f"  Période: {df.index.min()} à {df.index.max()}")
            
            return df
        except Exception as e:
            print(f"❌ Erreur lors de la récupération des données: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"   Réponse: {e.response.text}")
            raise

    def decode_token_info(self):
        """Décode et affiche les informations du token JWT (sans vérification de signature)"""
        if not self.access_token1:
            return None
            
        try:
            # Extraction du payload (partie centrale du JWT)
            parts = self.access_token1.split('.')
            if len(parts) != 3:
                return None
                
            # Ajout du padding si nécessaire
            payload = parts[1]
            padding = len(payload) % 4
            if padding:
                payload += '=' * (4 - padding)
                
            # Décodage base64
            decoded = base64.urlsafe_b64decode(payload)
            token_data = json.loads(decoded)
            
            # print("\n🔍 Informations du token:")
            # print(f"  - User ID: {token_data.get('uid', 'N/A')}")
            # print(f"  - Client ID: {token_data.get('cid', 'N/A')}")
            # print(f"  - Application ID: {token_data.get('aid', 'N/A')}")
            # print(f"  - Expiration: {token_data.get('exp', 'N/A')}")
            # if 'exp' in token_data:
            #     exp_date = datetime.fromtimestamp(int(token_data['exp']))
            #     print(f"    ({exp_date})")
            # print(f"  - Issuer: {token_data.get('iss', 'N/A')}")
            
            return token_data
        except Exception as e:
            print(f"⚠ Impossible de décoder le token: {e}")
            return None
        
    def get_access_token(self):
        """Récupère le token d'accès depuis l'endpoint Azure"""
        try:
            response = requests.get(self.token_url)
            response.raise_for_status()
            data = response.json()
            self.access_token1 = data['access_token']
            # print("✓ Token récupéré avec succès")
            # print(f"  Token (premiers caractères): {self.access_token1[:50]}...")
            self.decode_token_info()
            return self.access_token1
        except Exception as e:
            print(f"❌ Erreur lors de la récupération du token: {e}")
            raise
    
    def _get_headers(self):
        """Retourne les headers nécessaires pour les requêtes API"""
        if not self.access_token1:
            self.get_access_token()
        return {
            'Authorization': f'BEARER {self.access_token1}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def get_market_price(self, uic: int, asset_type: str = 'FxSpot'):
        """
        Récupère les prix Bid/Ask actuels pour un instrument donné.
        Exemple: uic=21, asset_type='FxSpot' pour EURUSD.
        """
        # Utilisation de l'URL de base définie dans la classe
        url = f"{self.API_BASE_LIVE}/trade/v1/infoprices"
        
        params = {
            'Uic': uic,
            'AssetType': asset_type,
            'FieldGroups': 'Quote,DisplayAndFormat'
        }

        try:
            # On utilise self._session qui possède déjà les headers si login_live_code() a été appelé
            # Sinon, on tente d'utiliser les headers du token Azure (access_token1)
            headers = self._session.headers
            if not headers.get('Authorization') and self.access_token1:
                headers = self._get_headers()

            response = self._session.get(url, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                quote = data.get('Quote', {})
                display = data.get('DisplayAndFormat', {})
                
                bid = quote.get('Bid')
                ask = quote.get('Ask')
                
                print(f"✓ {display.get('Description', 'Instrument')}: Bid: {bid}, Ask: {ask}")
                
                return {
                    "bid": bid,
                    "ask": ask,
                    "description": display.get('Description'),
                    "currency": display.get('Currency'),
                    "status": "OK"
                }
            else:
                print(f"❌ Erreur API Saxo ({response.status_code}): {response.text}")
                return None

        except Exception as e:
            print(f"❌ Erreur lors de la récupération du prix: {e}")
            return None

    def get_price_forced(self, uic, asset_type):
        """
        Récupère le prix en forçant la mise à jour du token depuis l'API Azure.
        Utile pour les instruments spécifiques comme les CFD ou les Turbos.
        """
        # 1. Récupération d'un token tout neuf
        try:
            token_res = requests.get(self.token_url, timeout=10)
            token_res.raise_for_status()
            token = token_res.json()['access_token']
        except Exception as e:
            return f"Erreur lors de la récupération du token Azure : {e}"

        # 2. Configuration de la requête
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        url = f"{self.API_BASE_LIVE}/trade/v1/infoprices"
        params = {
            'Uic': uic,
            'AssetType': asset_type,
            'FieldGroups': 'Quote,DisplayAndFormat,PriceInfoDetails'
        }

        # 3. Appel à Saxo
        try:
            res = requests.get(url, headers=headers, params=params, timeout=15)
            
            if res.status_code == 200:
                data = res.json()
                quote = data.get('Quote', {})
                price_details = data.get('PriceInfoDetails', {})
                display = data.get('DisplayAndFormat', {})
                
                # Extraction des données
                last_price = quote.get('LastPrice')
                bid = quote.get('Bid')
                ask = quote.get('Ask')
                last_close = price_details.get('LastClose')
                
                return {
                    "Instrument": display.get('Description'),
                    "Dernier_Cours": last_price,
                    "Achat_Bid": bid,
                    "Vente_Ask": ask,
                    "Clôture_Précédente": last_close,
                    "Statut_Prix": data.get('PriceStatus'),
                    "Devise": display.get('Currency'),
                    "Message": "Marché fermé ou flux restreint" if bid is None else "Flux Actif"
                }
            else:
                return {
                    "Erreur_Code": res.status_code,
                    "Message": res.text
                }
        except Exception as e:
            return f"Erreur lors de l'appel Saxo : {e}"

# END OF TEMPORARY FUNCTIONS









    # def get_product_current_prices(self, uic, asset_type):
    #     if not self._access_token:
    #         raise RuntimeError("Pas de token.")

    #     url = f"{self.API_BASE_LIVE}/trade/v1/infoprices"
    #     params = {
    #         'Uic': uic,
    #         'AssetType': asset_type,
    #         'FieldGroups': 'Quote,DisplayAndFormat,PriceInfoDetails'
    #     }

    #     r = self._session.get(url, params=params, timeout=30)
        
    #     if not r.ok:
    #         return f"Erreur API : {r.status_code}"

    #     data = r.json()
    #     quote = data.get('Quote', {})
    #     price_details = data.get('PriceInfoDetails', {})
        
    #     # Récupération des valeurs
    #     bid = quote.get('Bid')
    #     ask = quote.get('Ask')
    #     last = quote.get('LastTraded') or quote.get('LastPrice')
    #     last_close = price_details.get('LastClose')

    #     # Analyse du statut des droits
    #     has_access = quote.get('PriceTypeAsk') != 'NoAccess'
        
    #     # Si on n'a pas accès au temps réel, on utilise la clôture comme prix par défaut
    #     display_price = last if last else last_close

    #     return {
    #         "Dernier_Prix": display_price,
    #         "Achat_Bid": bid,
    #         "Vente_Ask": ask,
    #         "Cloture_Precedente": last_close,
    #         "Statut_Flux": "LIVE" if has_access else "DIFFÉRÉ/NO_ACCESS",
    #         "Instrument": data.get('DisplayAndFormat', {}).get('Description'),
    #         "Message": "⚠️ Activez le flux Euronext dans SaxoTrader pour voir le Bid/Ask" if not has_access else "OK"
    #     }
    





    # def get_historical_data(self, uic, asset_type, horizon=1440, count=200, mode=None, time=None):
    #     """
    #     Récupère les données historiques OHLC pour un instrument.
        
    #     Args:
    #         uic (int): Code de l'instrument (ex: 21 pour EUR/USD)
    #         asset_type (str): Type d'actif (FxSpot, Stock, WarrantKnockOut, etc.)
    #         horizon (int): Intervalle en minutes (1, 5, 15, 60, 1440=Daily)
    #         count (int): Nombre de bougies à récupérer (max 1200)
    #         mode (str): 'From' (depuis une date) ou 'UpTo' (jusqu'à une date)
    #         time (str): Date au format ISO (ex: '2026-02-13T00:00:00Z')
        
    #     Returns:
    #         list: Liste de dictionnaires contenant les données OHLC
    #     """
    #     if not self._access_token:
    #         raise RuntimeError("Pas de token – appelle login_live_code() d'abord.")

    #     url = f"{self.API_BASE_LIVE}/chart/v3/charts"
        
    #     params = {
    #         'Uic': uic,
    #         'AssetType': asset_type,
    #         'Horizon': horizon,
    #         'Count': count,
    #         'FieldGroups': 'Data'
    #     }

    #     # Ajout des filtres temporels si spécifiés
    #     if mode and time:
    #         params['Mode'] = mode
    #         params['Time'] = time

    #     r = self._session.get(url, params=params, timeout=30)
        
    #     if not r.ok:
    #         print(f"🚨 Erreur historique ({r.status_code}): {r.text}")
    #         r.raise_for_status()

    #     data = r.json()
    #     samples = data.get('Data', [])
        
    #     print(f"✓ {len(samples)} barres récupérées pour l'UIC {uic}")
    #     return samples
    
    # def get_historical_df(self, uic, asset_type, horizon=1440, count=200):
    #     """Récupère l'historique et retourne un Pandas DataFrame formaté"""
    #     samples = self.get_historical_data(uic, asset_type, horizon, count)
        
    #     if not samples:
    #         return pd.DataFrame()
            
    #     df = pd.DataFrame(samples)
    #     df['Time'] = pd.to_datetime(df['Time'])
    #     df.set_index('Time', inplace=True)
        
    #     # Nettoyage automatique pour le Forex (moyenne Bid/Ask)
    #     if 'OpenBid' in df.columns:
    #         for col in ['Open', 'High', 'Low', 'Close']:
    #             df[col] = (df[f'{col}Bid'] + df[f'{col}Ask']) / 2
                
    #     return df
    
