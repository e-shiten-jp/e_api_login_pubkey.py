# -*- coding: utf-8 -*-
# Copyright (c) 2021 Tachibana Securities Co., Ltd. All rights reserved.

# 2021.06.24,   yo.
# 2022.10.20 reviced,   yo.
# 2025.07.27 reviced,   yo.
# 2026.05.16 reviced,   yo.
# 2026.05.30 reviced,   yo
#
# 立花証券ｅ支店ＡＰＩ利用のサンプルコード
#
# 動作確認
# Python 3.13.5 / debian13
# API v4r9
#
# 機能: ログインして、仮想URL（1日券）を取得します。
#
# 利用方法: 
# 次の2つのファイルを準備してください。
# 1）接続情報ファイル: "./e_api/file_url_info.txt"に口座情報を記入します。
#   設定情報は、API接続先、表示形式指定です。
#   ユーザーID、第１暗証番号、第2暗証番号は、PKIログインでは使用しないので設定不要です。
#   デモ環境への接続のサンプル
#   {
#	    "sUrl":"https://demo-kabuka.e-shiten.jp/e_api_v4r9/",
#	    "sJsonOfmt":"5"
#   }
# 
# 2）第2パスワード保存ファイル：./e_api/.pki/passwd2.txt
# ログインでは使いません。注文、訂正、取り消しで使います。
# 第2パスワードを平文でそのまま保存します。改行や制御文字を入れないでください。 
# 権限設定は、600です。
# 
# ファイルの準備ができたら、githubの同じレポジトリ内にある
# setup_manyual.html
# をダウンロードし、ブラウザーで開き、設定を進めてください。
# 
# 事前準備は以上です。
# 
# 
# その他の説明
# 取得した仮想urlは、fname_login_response（ = "e_api_login_response.txt"）で
# 定義したファイルに保存します。
#
# p_noは、fname_info_p_no（ = "e_api_info_p_no.txt"）で定義したファイルに
# 保存します。
#
# == ご注意: ========================================
#   本番環境にに接続した場合、実際に市場に注文が出ます。
#   市場で約定した場合取り消せません。
# ==================================================
#
#

"""
立花証券e支店API - API接続・自動実行メインプログラム（再起動・エラー耐性強化版）

機能: 環境変数からセキュアに復号鍵を取得して秘密鍵をメモリ上に展開し、
      APIにログインして復号済みの仮想URL（1日券）を隠しフォルダに出力します。
      通信タイムアウトや一時的なネットワークエラーに対する自動リトライ機能を搭載。
"""

import base64
import datetime
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path
import urllib3
from urllib3.exceptions import MaxRetryError, TimeoutError

# 暗号化・復号用ライブラリ
from cryptography.fernet import Fernet
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

# =========================================================================
# --- 設定項目（定数定義：セットアップマニュアルに完全準拠） ---
# =========================================================================
CONFIG_FILE = "./.pki/secure_config.enc"            # 暗号化設定ファイル
FNAME_URL_INFO = "file_url_info.txt"                # API接続情報ファイル
FNAME_LOGIN_RESPONSE = "./.pki/file_login_response.txt"  # ログイン応答保存先
FNAME_INFO_P_NO = "file_info_p_no.txt"              # p_no保存ファイル

# --- 通信堅牢化のための設定項目 ---
API_TIMEOUT_SECONDS = 15.0  # タイムアウト時間（秒）: 応答がない場合15秒で切り上げる
MAX_RETRY_COUNT = 3         # 最大リトライ回数: 通信エラー時に自動再試行する回数
RETRY_INTERVAL_SECONDS = 5  # リトライ間隔（秒）: 再試行する前に待機する時間
# =========================================================================


# --- 構造体・クラス定義 --------------------------------------------------

class ClassDefAccountProperty:
    """接続情報属性クラス"""
    def __init__(self):
        self.sAuthId = ''
        self.sSecondPassword = ''   # 第2パスワード
        self.sUrl = ''              # 接続先URL
        self.sJsonOfmt = '5'        # 返り値の表示形式指定


class ClassDefLoginProperty:
    """ログイン属性クラス（マニュアルの戻り値定義に準拠）"""
    def __init__(self):
        self.p_no = 1
        self.sJsonOfmt = ''
        self.sResultCode = ''
        self.sResultText = ''
        self.sZyoutoekiKazeiC = ''
        self.sSecondPasswordOmit = ''
        self.sLastLoginDate = ''
        self.sSogoKouzaKubun = ''
        self.sHogoAdukariKouzaKubun = ''
        self.sFurikaeKouzaKubun = ''
        self.sGaikokuKouzaKubun = ''
        self.sMRFKouzaKubun = ''
        self.sTokuteiKouzaKubunGenbutu = ''
        self.sTokuteiKouzaKubunSinyou = ''
        self.sTokuteiKouzaKubunTousin = ''
        self.sTokuteiHaitouKouzaKubun = ''
        self.sTokuteiKanriKouzaKubun = ''
        self.sSinyouKouzaKubun = ''
        self.sSakopKouzaKubun = ''
        self.sMMFKouzaKubun = ''
        self.sTyukokufKouzaKubun = ''
        self.sKawaseKouzaKubun = ''
        self.sHikazeiKouzaKubun = ''
        self.sKinsyouhouMidokuFlg = ''
        self.sUrlRequest = ''
        self.sUrlMaster = ''
        self.sUrlPrice = ''
        self.sUrlEvent = ''
        self.sUrlEventWebSocket = ''
        self.sUpdateInformWebDocument = ''
        self.sUpdateInformAPISpecFunction = ''


# --- 共通ユーティリティ関数 ----------------------------------------------

def func_p_sd_date(dt_now):
    """システム時刻を API規定書式 "YYYY.MM.DD-hh:mm:ss.sss" の文字列に変換"""
    str_date = dt_now.strftime("%Y.%m.%d-%H:%M:%S")
    str_ms = f"{dt_now.microsecond:06d}"[:3]
    return f"{str_date}.{str_ms}"


def func_replace_urlencode(str_input):
    """URLエンコード文字の変換 (Python標準関数による安全なエスケープ)"""
    # パスワードやIDに含まれる「#」や「+」等の記号を安全にエンコードします
    return urllib.parse.quote(str_input, safe='')


def func_read_from_file(str_fname):
    """ファイルから文字情報を一括読み込み（BOMを自動排除）"""
    try:
        return Path(str_fname).read_text(encoding='utf-8-sig')
    except IOError as e:
        print(f"[エラー] ファイルを読み込めません: {str_fname}")
        raise e


def func_write_to_file(str_fname_output, str_data):
    """ファイルに書き込み、Linux環境向けに権限を所有者のみ(600)に制限"""
    try:
        path_out = Path(str_fname_output)
        path_out.parent.mkdir(parents=True, exist_ok=True) # ディレクトリがない場合は自動作成
        path_out.write_text(str_data, encoding='utf-8')
        
        # ファイル権限を600（所有者のみ読み書き）に設定
        os.chmod(str_fname_output, 0o600)
    except IOError as e:
        print(f"[エラー] ファイルに書き込めません: {str_fname_output}")
        raise e


def func_save_p_no(str_fname_output, int_p_no):
    """p_noを保存するためのJSONファイルを生成"""
    p_no_dict = {"p_no": str(int_p_no)}
    json_data = json.dumps(p_no_dict, indent=4)
    func_write_to_file(str_fname_output, json_data)
    print(f'現在の "p_no" を保存しました。 p_no = {int_p_no} -> {str_fname_output}')


def func_make_url_request_from_dic(auth_flg, url_target, work_dic_req):
    """API問合せ用完全URL（クエリパラメータ付）を作成"""
    str_url = url_target
    if auth_flg:
        str_url = urllib.parse.urljoin(str_url, 'auth/')
    
    # パラメータ部分を整形
    json_param = json.dumps(work_dic_req, indent=4, ensure_ascii=False)
    return f"{str_url}?{json_param}"


def func_api_req(str_request_method, str_url): 
    """
    APIリクエストの送信と、Shift-JIS応答のデコード（リトライ・タイムアウト対応版）
    """
    print('--- 送信電文 -------------------------------------------')
    print(str_url)

    # urllib3用のタイムアウト制御オブジェクトを生成（接続・読み込みともに設定秒で制限）
    timeout_config = urllib3.Timeout(connect=API_TIMEOUT_SECONDS, read=API_TIMEOUT_SECONDS)
    http = urllib3.PoolManager()
    
    response_data = None
    status_code = None

    # 設定された最大試行回数分、ループで通信をトライ
    for attempt in range(1, MAX_RETRY_COUNT + 1):
        try:
            # 2回目以降のループ（再試行時）は、指定されたインターバル秒だけスリープを入れて待機
            if attempt > 1:
                print(f"[{attempt}/{MAX_RETRY_COUNT} 回目] 再接続を試みます...（{RETRY_INTERVAL_SECONDS}秒待機）")
                time.sleep(RETRY_INTERVAL_SECONDS)

            # リクエスト送信（タイムアウト設定を適用）
            req = http.request(str_request_method, str_url, timeout=timeout_config)
            status_code = req.status
            response_data = req.data
            break  # 例外が発生せず正常に通信できたらループを抜ける

        except (TimeoutError, MaxRetryError) as ce:
            # ネットワーク切断、サーバーハング、DNSエラー等の通信起因の例外をここでキャッチ
            print(f"\n[警告] 通信エラーが発生しました (試行: {attempt}/{MAX_RETRY_COUNT})")
            print(f"エラー詳細: {ce}")
            
            # 最大回数まで叩いてもダメだった場合は、復旧不可能と判断してカスタムエラーを発生させる
            if attempt == MAX_RETRY_COUNT:
                raise ConnectionError(
                    f"APIサーバーへの接続に規定回数失敗しました。サーバーがメンテナンス中か、停止している可能性があります。\n"
                    f"設定されたタイムアウト時間: {API_TIMEOUT_SECONDS}秒"
                )
        except Exception as ex:
            # 想定外の致命的な例外が発生した場合は、リトライ上限に達した時点でそのまま上位へレイズ
            print(f"\n[警告] 予期せぬネットワーク例外が発生しました: {ex}")
            if attempt == MAX_RETRY_COUNT:
                raise ex

    print(f"HTTP Status: {status_code}")

    # レスポンスデータをShift-JISからUTF-8文字列へ変換
    str_response = response_data.decode("shift-jis", errors="ignore")
    print('--- 受信電文 -------------------------------------------')
    print(str_response)
    print('--------------------------------------------------------')

    return str_response


def func_get_url_info(fname, class_account_property):
    """file_url_info.txt からAPI接続設定を取得"""
    str_url_info = func_read_from_file(fname)
    json_account_info = json.loads(str_url_info)

    class_account_property.sUrl = json_account_info.get('sUrl', '')
    class_account_property.sJsonOfmt = json_account_info.get('sJsonOfmt', '5')


# --- 暗号・復号コアロジック -----------------------------------------------

def decrypt_sUrl(encoded_encrypted_sUrl, private_key_obj):
    """APIから返された暗号化仮想URLを秘密鍵（RSAオブジェクト）で復号"""
    # 1. 復号器の準備 (セットアップマニュアル/規定書準拠: OAEPパディング / 内部ハッシュにSHA-256を使用)
    decryptor = PKCS1_OAEP.new(private_key_obj, hashAlgo=SHA256)

    # 2. Base64デコード処理（JSONパース時に混入する可能性のある前後の引用符や空白をクレンジング）
    clean_b64data = encoded_encrypted_sUrl.strip().replace('"', '')
    decoded_b64data = base64.b64decode(clean_b64data)
    
    # 3. 秘密鍵を用いたRSA復号の実行（バイトデータが返る）
    decrypted_bytes = decryptor.decrypt(decoded_b64data)
    
    # 4. バイト列をUTF-8文字列に変換し、BOMが混入しても除去できるよう utf-8-sig を明示
    return decrypted_bytes.decode("utf-8-sig").strip()


def func_login_pki(int_p_no, class_account_property):
    """PKI認証（秘密鍵ログイン）リクエストの組み立てと実行"""
    str_p_sd_date = func_p_sd_date(datetime.datetime.now())

    # リクエスト引数の組み立て
    dic_req_item = {
        "p_no": str(int_p_no),
        "p_sd_date": str_p_sd_date,
        "sCLMID": "CLMAuthLoginRequest",
        "sAuthId": class_account_property.sAuthId,
        "sJsonOfmt": class_account_property.sJsonOfmt
    }
    
    # ログインは常にPOSTメソッドを利用
    str_request_method = 'POST'
    str_url = func_make_url_request_from_dic(True, class_account_property.sUrl, dic_req_item)

    # API送信（内部のタイムアウト・自動リトライ機能を経由して電文を送信）
    str_api_response = func_api_req(str_request_method, str_url)
    return json.loads(str_api_response)


# --- メイン処理シーケンス ------------------------------------------------

def func_login(auth_id, private_key_obj):
    """ログインシーケンス全体の制御と応答の復号化保存"""
    my_account_property = ClassDefAccountProperty()

    # 1. 接続先情報の読み込みとIDの設定
    func_get_url_info(FNAME_URL_INFO, my_account_property)
    my_account_property.sAuthId = func_replace_urlencode(auth_id)

    # 2. p_noの初期化とファイル保存（ログイン時は 1 固定）
    my_login_property = ClassDefLoginProperty()
    func_save_p_no(FNAME_INFO_P_NO, my_login_property.p_no)
    
    print('\n== 立花証券API ログイン処理開始 ========================')
    dic_return = func_login_pki(my_login_property.p_no, my_account_property)
    
    # 3. ログインエラー判定
    int_p_errno = int(dic_return.get('p_errno', -1))
    int_sResultCode = int(dic_return.get('sResultCode', -1))
    
    if int_p_errno == 0 and int_sResultCode == 0:
        # 4. 書面未読チェック
        url_request_raw = dic_return.get('sUrlRequest', '')
        if len(url_request_raw) > 0:
            print('-> ログイン成功。公開鍵暗号化された仮想URLの復号を行います...')
            
            # 各機能の仮想URL（暗号化された状態の1日券）を秘密鍵で1つずつ復号して置換
            target_url_keys = ['sUrlRequest', 'sUrlMaster', 'sUrlPrice', 'sUrlEvent', 'sUrlEventWebSocket']
            for key in target_url_keys:
                if dic_return.get(key):
                    dic_return[key] = decrypt_sUrl(dic_return[key], private_key_obj)
            
            # ファイル保存用に綺麗なJSON文字列へ変換
            json_data = json.dumps(dic_return, indent=4, ensure_ascii=False)
            
            # 復号済みログインレスポンスの書き込み保存
            func_write_to_file(FNAME_LOGIN_RESPONSE, json_data)
            print(f'【成功】復号したログインレスポンスを保存しました: {FNAME_LOGIN_RESPONSE}')
            print('========================================================')
            print(f"交付書面更新予定日 (sUpdateInformWebDocument): {dic_return.get('sUpdateInformWebDocument')}")
            print(f"APIリリース予定日  (sUpdateInformAPISpecFunction): {dic_return.get('sUpdateInformAPISpecFunction')}")
            print('========================================================')
        else:
            print('\n[警告] 契約締結前書面が未読状態です。')
            print('APIは利用できません。ブラウザから標準Web画面を開き、書面を確認してください。')
            sys.exit(1)
    else:
        print('\n[エラー] ログインに失敗しました。')
        print(f"p_errno: {dic_return.get('p_errno')} ({dic_return.get('p_err')})")
        print(f"sResultCode: {dic_return.get('sResultCode')} ({dic_return.get('sResultText')})")
        sys.exit(1)


def load_api_credentials():
    """環境変数および暗号化ファイルから認証に必要な情報をメモリ上に安全展開"""
    # 1. systemd等から注入された環境変数の取得
    fernet_key_str = os.environ.get("API_DECRYPT_KEY")
    if not fernet_key_str:
        raise RuntimeError(
            "復号用の環境変数 'API_DECRYPT_KEY' がシステムに設定されていません。\n"
            "「セットアップマニュアル.html」の手順に沿って環境変数が正しくセットされているか確認してください。"
        )
    
    # 2. セキュア暗号化ファイルのロード
    config_path = Path(CONFIG_FILE)
    if not config_path.exists():
        raise FileNotFoundError(f"暗号化設定ファイルが見つかりません: {config_path.resolve()}")
    
    # 3. 暗号化された設定ファイルの内容をバイナリとして一括読み込み
    encrypted_bytes = config_path.read_bytes()

    # 4. 共通鍵（Fernet）デクリプタを初期化し、バイナリを復号
    cipher = Fernet(fernet_key_str.encode())
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    
    # 5. 復号されたプレーンな文字列（JSON）をディクショナリにデコード
    config = json.loads(decrypted_bytes.decode('utf-8'))
    auth_id = config["auth_id"]
    
    # 6. JSON内に格納されていたPEM形式のテキストから、RSA秘密鍵オブジェクトをメモリ上にロード
    private_key_obj = RSA.import_key(config["private_key"])
    
    # 呼び出し元へ「認証ID」と「秘密鍵オブジェクト」を返す
    return auth_id, private_key_obj


def main():
    """プログラムのエントリポイント（通信エラーのキャッチ強化構造）"""
    try:
        # メモリ上へのセキュア展開（環境変数チェックとファイルの復号化ロード）
        my_auth_id, my_private_key = load_api_credentials()
        print("【セキュリティ認証】秘密鍵のメモリ展開に成功しました。")
        
        # ログインメイン処理の実行
        func_login(my_auth_id, my_private_key)
        
        print(f"利用中のAuthID: {my_auth_id}")
        print("API自動ログイン処理がすべて正常に完了しました。")
        
    except ConnectionError as ce:
        # func_api_req 内で規定回数リトライをオーバーした通信エラーをきれいにトラップ
        print(f"\n【通信エラーを検知しました】\n{ce}", file=sys.stderr)
        print("時間を置いて再起動するか、サーバーの稼働スケジュールを確認してください。", file=sys.stderr)
        sys.exit(1)
        
    except Exception as e:
        # 通信以外のバグやファイルIO例外など、その他の予期せぬ実行エラーをまとめて捕捉
        print(f"\n【実行エラー】API自動ログイン処理の実行に失敗しました: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()