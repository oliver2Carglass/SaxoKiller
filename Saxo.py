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
    TOKEN_FILE = "saxo_tokens.json"
    
    def __init__(self, app_key, app_secret, app_name,
                 redirect_uri="http://127.0.0.1:8001/callback",
                 app_id=None, bind_all=False, wait_timeout=180):
        
        self._app_key = app_key
        self._app_secret = app_secret
        self._app_name = app_name
        self._app_id = app_id
        self._redirect_uri = redirect_uri
        self._bind_all = bind_all
        self._wait_timeout = wait_timeout
        self._access_token = None
        self._refresh_token = None
        self._session = requests.Session()
        self._expected_state = None

        # Configuration par défaut des headers de session
        self._session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
        
        # 1. Charger les tokens si le fichier existe déjà
        self._load_tokens_from_file()

        # 2. Si un access_token a été chargé, l'injecter dans la session
        if self._access_token:
            self._session.headers.update({
                "Authorization": f"Bearer {self._access_token}"
            })
            print("🔑 Token chargé et session prête.")


       




    def _save_tokens_to_file(self):
        """Sauvegarde les jetons dans un fichier local."""
        data = {
            "access_token": self._access_token,
            "refresh_token": self._refresh_token,
            "updated_at": datetime.datetime.now().isoformat()
        }
        with open(self.TOKEN_FILE, "w") as f:
            json.dump(data, f)
        print("💾 Jetons sauvegardés localement.")
    
    def _load_tokens_from_file(self):
        """Charge les jetons si le fichier existe."""
        if os.path.exists(self.TOKEN_FILE):
            try:
                with open(self.TOKEN_FILE, "r") as f:
                    data = json.load(f)
                    self._access_token = data.get("access_token")
                    self._refresh_token = data.get("refresh_token")
                
                # Appliquer le token chargé à la session
                if self._access_token:
                    self._session.headers.update({
                        "Authorization": f"Bearer {self._access_token}",
                        "Accept": "application/json",
                        "Content-Type": "application/json"
                    })
                print("📂 Jetons chargés depuis le fichier.")
            except Exception as e:
                print(f"⚠️ Erreur chargement fichier token : {e}")

    def get_accounts(self):
        url = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
        r = self._session.get(url, timeout=30)
        r.raise_for_status()
        return r.json().get("Data", [])
  
    def get_token(self):
        return self._access_token
    
    def smart_login(self):
            """
            Méthode 'intelligente' à appeler au début de ton script :
            1. Teste si le token actuel marche.
            2. Sinon, tente un refresh.
            3. Sinon, lance le login complet (navigateur).
            """
            # 1. Tester le token actuel avec un appel léger
            if self._access_token:
                try:
                    url = f"{self.API_BASE_LIVE}/port/v1/users/me"
                    r = self._session.get(url, timeout=5)
                    if r.ok:
                        print("✅ Session toujours active.")
                        return
                except:
                    pass

            # 2. Tenter le refresh
            if self.refresh_access_token():
                return

            # 3. Login complet si tout a échoué
            self.login_live_code()
            self._save_tokens_to_file()
    
    def refresh_access_token(self):
        """Utilise le refresh_token pour obtenir un nouvel access_token sans login."""
        if not self._refresh_token:
            return False

        print("🔄 Renouvellement du token via Refresh Token...")
        basic_auth = base64.b64encode(f"{self._app_key}:{self._app_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {basic_auth}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token
        }
        
        try:
            r = requests.post(self.TOKEN_URL_LIVE, headers=headers, data=data, timeout=30)
            r.raise_for_status()
            token_data = r.json()
            
            self._access_token = token_data["access_token"]
            # Saxo peut renvoyer un nouveau refresh_token ou garder le même
            if "refresh_token" in token_data:
                self._refresh_token = token_data["refresh_token"]
            
            self._session.headers.update({"Authorization": f"Bearer {self._access_token}"})
            self._save_tokens_to_file()
            print("✅ Token rafraîchi avec succès.")
            return True
        except Exception as e:
            print(f"❌ Échec du refresh : {e}")
            return False
        
    # --- Dans la classe SaxoClient ---

    class OAuthCallbackHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            # Ignorer les requêtes inutiles (favicon, etc.)
            if "/callback" not in self.path:
                self.send_response(204)
                self.end_headers()
                return

            parsed = urlparse.urlparse(self.path)
            qs = urlparse.parse_qs(parsed.query)
            
            # On stocke les valeurs dans l'objet serveur
            self.server.code = qs.get("code", [None])[0]
            self.server.state = qs.get("state", [None])[0]

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>OK</h1><p>Connexion reussie. Vous pouvez fermer cette fenetre.</p></body></html>")

    def _wait_for_code(self):
        host, port = self._extract_host_port()
        bind_host = "0.0.0.0" if self._bind_all else host
        
        # Autoriser la réutilisation de l'adresse pour éviter l'erreur "Address already in use"
        socketserver.TCPServer.allow_reuse_address = True
        
        with socketserver.TCPServer((bind_host, port), self.OAuthCallbackHandler) as httpd:
            httpd.code = None
            httpd.state = None
            httpd.timeout = 1 # Empêche le blocage infini
            
            start = time.time()
            while httpd.code is None:
                if time.time() - start > self._wait_timeout:
                    raise TimeoutError(f"Callback non reçu dans {self._wait_timeout}s")
                httpd.handle_request() # Traite UNE requête
                
            return httpd.code, httpd.state

    def _extract_host_port(self):
        parsed = urlparse.urlparse(self._redirect_uri)
        host = parsed.hostname or "127.0.0.1"
        port = int(parsed.port or 80)
        return host, port


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
        # if state != self._expected_state:
        #     raise RuntimeError(f"State inattendu. Attendu={self._expected_state}, reçu={state}")
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
    
    import pandas as pd

    def get_positions(self, account_key: str = None, client_key: str = None):
        if not self._access_token:
            raise RuntimeError("Pas de token – appelle login_live_code() d'abord.")

        # 1️⃣ Récupération des clés si non fournies
        if not account_key or not client_key:
            url_acc = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
            r = self._session.get(url_acc, timeout=30)
            accs = r.json().get("Data", [])
            if not accs: 
                return pd.DataFrame()
            account_key, client_key = accs[0]["AccountKey"], accs[0].get("ClientKey")

        # 2️⃣ Appel NetPositions
        url_pos = f"{self.API_BASE_LIVE}/port/v1/netpositions"
        params = {
            "AccountKey": account_key,
            "ClientKey": client_key,
            "FieldGroups": "DisplayAndFormat,NetPositionBase,NetPositionView"
        }
        
        rp = self._session.get(url_pos, params=params, timeout=30)
        items = rp.json().get("Data", [])
        
        results = []
        for it in items:
            display = it.get("DisplayAndFormat", {})
            base = it.get("NetPositionBase", {})
            view = it.get("NetPositionView", {})
            opts = base.get("OptionsData", {}) 
            
            uic = base.get("Uic")
            asset_type = base.get("AssetType")
            qty = float(base.get("Amount") or 0)
            if qty == 0: continue

            # --- DÉTERMINATION DU SENS (CALL/PUT ou LONG/SHORT) ---
            # On regarde d'abord le champ PutCall, sinon la perspective, sinon le nom
            put_call = opts.get("PutCall")
            direction = "Long" # Par défaut
            
            if put_call in ["Call", "Put"]:
                direction = put_call
            else:
                # Fallback sur TradePerspective ou analyse du nom
                perspective = opts.get("TradePerspective")
                if perspective in ["Long", "Short"]:
                    direction = perspective
                elif "Long" in display.get("Description", ""):
                    direction = "Call"
                elif "Short" in display.get("Description", ""):
                    direction = "Put"

            # --- DONNÉES DE CALCUL ---
            underlying_price = float(view.get("UnderlyingCurrentPrice") or 0.0)
            curr_price = float(view.get("CurrentPrice") or 0.0)
            strike = float(opts.get("Strike") or opts.get("FinancingLevel") or 0.0)
            ratio = float(opts.get("Ratio") or 1.0)

            # --- CALCUL DU LEVIER PRÉCIS ---
            leverage = 0.0
            if underlying_price > 0 and strike > 0 and (underlying_price != strike):
                leverage = underlying_price / abs(underlying_price - strike)
            elif underlying_price > 0 and curr_price > 0:
                leverage = underlying_price / (curr_price * ratio)

            results.append({
                "name": display.get("Description"),
                "type": direction,  # Ajout du sens ici
                "uic": uic,
                "quantity": qty,
                "buying_price": float(view.get("AverageOpenPrice") or 0.0),
                "current_price": curr_price,
                "underlying_price": underlying_price,
                "strike": round(strike, 2),
                "leverage": round(leverage, 2),
                "pnl (€)": round(float(view.get("ProfitLossOnTrade", 0.0)), 2),
                "currency": display.get("Currency")
            })

        # 3️⃣ Création du DataFrame et calculs finaux
        df = pd.DataFrame(results)
        
        if not df.empty:
            df['pnl (%)'] = 0.0
            mask = (df['buying_price'] > 0) & (df['quantity'] != 0)
            df.loc[mask, 'pnl (%)'] = round((df['pnl (€)'] / (df['buying_price'] * df['quantity'])) * 100, 2)
            
        return df

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

    def get_product_full_details(self, uic, asset_type):
        """Récupère les détails techniques (TickSize, devise, etc.)"""
        url = f"{self.API_BASE_LIVE}/ref/v1/instruments/details"
        params = {"Uics": uic, "AssetTypes": asset_type}
        r = self._session.get(url, params=params)
        r.raise_for_status()
        data = r.json().get("Data", [])
        return data[0] if data else None


    def get_product_trading_details(self, uic, asset_type='MiniFuture'):
        """
        Analyse les détails techniques d'un produit (Turbo/MiniFuture)
        et calcule le levier et la distance à la barrière en temps réel.
        """
        # 1. Récupérer les détails statiques (ce que tu as posté)
        details = self.get_product_full_details(uic, asset_type)
        if not details:
            return None

        # 2. Récupérer le prix actuel (nécessaire pour le levier et la distance)
        price_info = self.get_market_price(uic, asset_type)
        current_price = price_info.get('ask') if price_info else None

        # 3. Extraction et calculs
        # Ratio : souvent 10 ou 100 sur les turbos, ici 5.0 dans ton exemple
        ratio = details.get('Ratio', 1.0)
        stop_level = details.get('StopLossLevel')
        underlying_name = details.get('UnderlyingDescription')
        
        levier = None
        distance_barriere_pct = details.get('BarrierDistance') # Saxo le fournit déjà

        if current_price and current_price > 0:
            # Calcul du levier : (Prix Sous-jacent / (Prix Turbo * Ratio))
            # Note : Saxo fournit souvent le levier directement dans d'autres endpoints, 
            # mais ici on peut l'estimer si on a le prix du sous-jacent ou via le prix du Turbo.
            # Formule simplifiée du levier Turbo : (Prix Sous-jacent / (Prix Turbo * Ratio))
            # Comme on n'a pas forcément le prix du sous-jacent là tout de suite :
            # On peut aussi le calculer par : 1 / ((Prix Turbo * Ratio) / Prix Sous-jacent)
            pass

        return {
            "nom": details.get('Description'),
            "sous_jacent": underlying_name,
            "type_produit": details.get('AssetType'), # MiniFuture / Turbo
            "direction": details.get('TradePerspective'), # Long ou Short
            "prix_unitaire": current_price,
            "devise": details.get('CurrencyCode'),
            "barriere_desactivation": stop_level,
            "distance_barriere_pct": round(distance_barriere_pct, 2) if distance_barriere_pct else None,
            "ratio": ratio,
            "uic_sous_jacent": details.get('UnderlyingUic'),
            "tick_size": details.get('TickSize'),
            "statut": details.get('TradingStatus')
        }



    def get_open_orders_full_info(self):
        """Liste les ordres en attente (Working Orders)"""
        url_acc = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
        acc = self._session.get(url_acc).json()['Data'][0]
        
        url = f"{self.API_BASE_LIVE}/port/v1/orders"
        params = {"AccountKey": acc["AccountKey"], "ClientKey": acc["ClientKey"]}
        r = self._session.get(url, params=params)
        r.raise_for_status()
        return r.json().get("Data", [])
    
    def get_open_orders(self):
        """Version simplifiée de get_open_orders_full_info() pour juste les infos essentielles comme un df."""
        orders = self.get_open_orders_full_info()
        simplified = []
        for o in orders:
            simplified.append({
                "OrderId": o.get("OrderId"),
                "Uic": o.get("Uic"),
                "AssetType": o.get("AssetType"),
                "Amount": o.get("Amount"),
                "BuySell": o.get("BuySell"),
                "OrderPrice": o.get("Price"),
                "Status": o.get("Status")
            })
        return pd.DataFrame(simplified)
        

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


    def get_chart_data_range(self, uic, start_time, end_time, asset_type='Stock', horizon=1440):
        """
        Récupère les données historiques entre deux dates.
        Note: asset_type doit correspondre au type réel de l'instrument (ex: 'Stock', 'CfdOnStock', 'WarrantKnockOut').
        """
        if isinstance(start_time, str):
            start_dt = pd.to_datetime(start_time)
        else:
            start_dt = start_time
            
        if isinstance(end_time, str):
            end_dt = pd.to_datetime(end_time)
        else:
            end_dt = end_time

        # Calcul du nombre de barres
        delta_minutes = (end_dt - start_dt).total_seconds() / 60
        needed_count = int(delta_minutes / horizon) + 2 
        
        # Limite de sécurité Saxo
        if needed_count > 1200:
            needed_count = 1200

        # Format ISO avec 'Z' requis par Saxo
        end_time_iso = end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

        print(f"📊 Mode: UpTo | Date: {end_time_iso} | Count: {needed_count} | Asset: {asset_type}")
        
        return self.get_chart_data(
            uic=uic,
            asset_type=asset_type,
            horizon=horizon,
            count=needed_count,
            mode='UpTo',
            time=end_time_iso
        )

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
    
    def _get_headers(self):
        """Retourne les headers nécessaires pour les requêtes API"""

        return {
            'Authorization': f'BEARER {self._access_token}',
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
            if not headers.get('Authorization') and self._access_token:
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
        # 2. Configuration de la requête
        headers = {
            'Authorization': f'Bearer {self._access_token}',
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


    def get_last_transactions(
        self,
        n: int = 50,
        account_key: str = None,
        client_key: str = None,
        from_date: str = None,    # "YYYY-MM-DD" conseillé
        to_date: str = None,      # "YYYY-MM-DD" conseillé
        asset_types: list | None = None,
        uics: list | None = None,
        events: list | None = None,
        to_open_or_close: list | None = None,
        transaction_type: str | None = None,  # << NEW: ex. "Trade"
        as_dataframe: bool = True
    ):
        """
        Récupère les X dernières transactions via /hist/v1/transactions.

        Notes :
        - Paramètres disponibles : $top/$skip, ClientKey, AccountKeys, FromDate/ToDate, Uics,
            Events, TransactionType (=Trade, CashBooking, ...), etc.  [1](https://www.developer.saxo/openapi/learn/openapi-request-response)
        - 'TransactionTime' = date d'exécution ; 'ValueDate' = date de valeur (peut être future).  [2](https://developer.saxobank.com/openapi/learn/trade-details)
        """
        if not self._access_token:
            raise RuntimeError("Pas de token – appelle smart_login() ou login_live_code() d'abord.")

        # 0) Fenêtre par défaut si absente (J-365 -> J) : recommandé sur ce service d'historique
        if not from_date or not to_date:
            import datetime as _dt
            today = _dt.date.today()
            one_year = today.replace(year=today.year - 1)
            from_date = from_date or one_year.isoformat()
            to_date   = to_date   or today.isoformat()

        # 1) Récupérer AccountKey/ClientKey si non fournis
        if not account_key or not client_key:
            url_acc = f"{self.API_BASE_LIVE}/port/v1/accounts/me"
            r_acc = self._session.get(url_acc, timeout=30)
            try:
                r_acc.raise_for_status()
            except Exception as e:
                raise RuntimeError(f"Erreur /accounts/me : {getattr(e, 'response', None) and e.response.text}") from e
            accs = (r_acc.json() or {}).get("Data", []) or []
            if not accs:
                raise RuntimeError("Aucun compte trouvé via /accounts/me")
            acc = accs[0]
            account_key = account_key or acc["AccountKey"]
            client_key = client_key or (acc.get("ClientKey") or acc.get("ClientId") or acc.get("ClientKeyId"))

        # 2) Endpoint Transactions (historique)
        base_url = f"{self.API_BASE_LIVE}/hist/v1/transactions"

        # Pagination
        page_size = 100 if n > 100 else max(min(n, 100), 1)

        # Build params
        def build_params(top: int, skip: int):
            p = {
                "$top": top,
                "$skip": skip,
                "ClientKey": client_key,
                "AccountKeys": account_key,
                "FromDate": from_date,
                "ToDate": to_date
            }
            if asset_types:
                p["AssetTypes"] = ",".join(asset_types)
            if uics:
                p["Uics"] = ",".join(str(x) for x in uics)
            if events:
                p["Events"] = ",".join(events)
            if to_open_or_close:
                p["ToOpenOrClose"] = ",".join(to_open_or_close)
            if transaction_type:
                p["TransactionType"] = transaction_type  # << clé documentée  [1](https://www.developer.saxo/openapi/learn/openapi-request-response)
            return p

        all_items, fetched, skip = [], 0, 0

        # 3) Boucle de pagination
        while fetched < n:
            top = min(page_size, n - fetched)
            params = build_params(top=top, skip=skip)
            try:
                r = self._session.get(base_url, params=params, timeout=30)
                if not r.ok:
                    try:
                        print(f"🚨 SAXO Transactions DEBUG {r.status_code} : {r.text}")
                        print(f"   Params: {params}")
                    except Exception:
                        pass
                    r.raise_for_status()
            except Exception as e:
                detail = getattr(e, "response", None) and e.response.text
                raise RuntimeError(f"Transactions API error: {detail}") from e

            payload = r.json() or {}
            items = payload.get("Data", []) or []
            all_items.extend(items)
            fetched += len(items)

            if len(items) < top or fetched >= n or not payload.get("__next"):
                break
            skip += top

        # 4) Tri par date d’exécution en priorité
        def _extract_dt(d):
            return (
                d.get("TransactionTime") or
                d.get("Time") or
                d.get("BookingDate") or
                d.get("ValueDate") or
                ""
            )
        all_items.sort(key=_extract_dt, reverse=True)

        # 5) Retour brut si demandé
        if not as_dataframe:
            return all_items[:n]

        # 6) DataFrame
        try:
            import pandas as _pd
            df = _pd.DataFrame(all_items[:n])
            # Colonnes utiles si présentes
            ordered = [
                "TransactionTime", "Time", "BookingDate", "ValueDate",
                "TransactionType", "BuySell", "ToOpenOrClose",
                "Price", "Amount", "Currency",
                "Uic", "AssetType", "Symbol", "Description", "TradeId"
            ]
            keep = [c for c in ordered if c in df.columns]
            df = df[keep] if keep else _pd.DataFrame(columns=ordered)

            for tcol in ["TransactionTime", "Time", "BookingDate", "ValueDate"]:
                if tcol in df.columns:
                    df[tcol] = _pd.to_datetime(df[tcol], errors="coerce")

            sort_col = next((c for c in ["TransactionTime", "Time", "BookingDate", "ValueDate"] if c in df.columns), None)
            if sort_col:
                df = df.sort_values(by=sort_col, ascending=False)

            return df
        except Exception:
            return all_items[:n]


    def get_last_trades(
        self,
        n: int = 50,
        account_key: str = None,
        client_key: str = None,
        uic: int | None = None,
        from_date: str | None = None,  # "YYYY-MM-DD"
        to_date: str | None = None,    # "YYYY-MM-DD"
        as_dataframe: bool = True
    ):
        """
        Retourne les 'n' dernières exécutions (TransactionType='Trade') et déplie
        la structure imbriquée renvoyée par /hist/v1/transactions :
        - TradeTimestamp (exécution réelle, depuis Trades[].TradeExecutionTime)
        - ValueDate (date de valeur, peut être future)
        - BuySell, ToOpenOrClose
        - Price, Quantity (TradedQuantity) + BookedAmount (cash)
        - Currency
        - Uic, TradeId, Description

        Références :
        - Paramètre TransactionType documenté sur l'endpoint Transactions. [2](https://www.developer.saxo/openapi/learn/openapi-request-response)
        - Sémantique ValueDate vs horodatage d'exécution dans Account History. [1](https://developer.saxobank.com/openapi/learn/trade-details)
        """

        # 1) Récupère l'historique côté API en demandant explicitement des trades
        raw = self.get_last_transactions(
            n=max(n * 3, 100),                  # marge pour filtrage/doublons
            account_key=account_key,
            client_key=client_key,
            from_date=from_date,
            to_date=to_date,
            uics=[uic] if uic else None,
            events=None,                        # on n'utilise pas Events ici
            asset_types=None,                   # éviter un filtre trop strict
            transaction_type="Trade",           # << clé officielle
            as_dataframe=False
        )

        # 2) Dépliage & normalisation
        rows = []
        for t in raw:
            # Champs top-level (cash / settlement / libellés)
            t_value_date = t.get("ValueDate") or (t.get("Bookings") or [{}])[0].get("ValueDate")
            t_booked_amt = t.get("BookedAmount")
            t_currency   = t.get("Currency")

            # Instrument
            instr = t.get("Instrument") or {}
            uic_val = instr.get("Uic") or t.get("Uic")
            desc    = instr.get("Description") or t.get("Description")
            price_ccy = instr.get("PriceCurrency")

            # Chaque "transaction" peut contenir 1..n éléments dans Trades[]
            trades_list = t.get("Trades") or []
            if not trades_list:
                # fallback : ligne minimale (rare), on garde quand même une trace
                rows.append({
                    "TradeTimestamp": t.get("TransactionTime") or t.get("Time") or t.get("Date") or t.get("BookingDate"),
                    "ValueDate": t_value_date,
                    "BuySell": t.get("Event"),             # Buy/Sell si dispo
                    "ToOpenOrClose": None,
                    "Price": None,
                    "Quantity": None,
                    "BookedAmount": t_booked_amt,
                    "Currency": t_currency or price_ccy,
                    "Uic": uic_val,
                    "TradeId": t.get("TradeId"),
                    "Description": desc,
                })
                continue

            for tr in trades_list:
                # Timestamp d’exécution prioritaire
                ts = tr.get("TradeExecutionTime") or t.get("TransactionTime") or t.get("Time") or t.get("Date") or t.get("BookingDate")

                # Sens du trade : priorité à TradeEventType (Bought/Sold), sinon Event (Buy/Sell),
                # sinon signe de TradedQuantity.
                side = None
                tev = tr.get("TradeEventType")   # "Bought" / "Sold"
                if tev in ("Bought", "Sold"):
                    side = "Buy" if tev == "Bought" else "Sell"
                elif t.get("Event") in ("Buy", "Sell"):
                    side = t.get("Event")
                else:
                    qty = tr.get("TradedQuantity")
                    if isinstance(qty, (int, float)):
                        side = "Buy" if qty and qty > 0 else ("Sell" if qty and qty < 0 else None)

                rows.append({
                    "TradeTimestamp": ts,
                    "ValueDate": t_value_date,
                    "BuySell": side,
                    "ToOpenOrClose": tr.get("ToOpenOrClose"),    # "ToOpen" / "ToClose"...
                    "Price": tr.get("Price"),
                    "Quantity": tr.get("TradedQuantity"),
                    "BookedAmount": t_booked_amt,                # cash booké (peut être signé)
                    "Currency": t_currency or price_ccy,
                    "Uic": uic_val,
                    "TradeId": tr.get("TradeId") or t.get("TradeId"),
                    "Description": desc,
                })

        # Si on veut du JSON brut
        if not as_dataframe:
            # Tri desc. par TradeTimestamp et coupe à n
            try:
                from datetime import datetime
                rows.sort(key=lambda r: r.get("TradeTimestamp") or "", reverse=True)
            except Exception:
                pass
            return rows[:n]

        # 3) DataFrame propre
        import pandas as pd
        df = pd.DataFrame(rows)

        # Garantir colonnes attendues même si vide
        expected_cols = [
            "TradeTimestamp","ValueDate","BuySell","ToOpenOrClose",
            "Price","Quantity","BookedAmount","Currency","Uic","TradeId","Description"
        ]
        for c in expected_cols:
            if c not in df.columns:
                df[c] = None

        # Casts & tri
        df["TradeTimestamp"] = pd.to_datetime(df["TradeTimestamp"], errors="coerce")
        df["ValueDate"] = pd.to_datetime(df["ValueDate"], errors="coerce")

        # Dédupe (au cas où plusieurs lignes référencent le même TradeId)
        if "TradeId" in df.columns:
            df = df.sort_values(by=["TradeTimestamp","TradeId"], ascending=[False, False])
            df = df.drop_duplicates(subset=["TradeId"], keep="first")

        # Ordonner & couper
        df = df[expected_cols].head(n)
        return df


