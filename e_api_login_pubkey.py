# -*- coding: utf-8 -*-
# Copyright (c) 2021 Tachibana Securities Co., Ltd. All rights reserved.

# 2021.06.24,   yo.
# 2022.10.20 reviced,   yo.
# 2025.07.27 reviced,   yo.
# 2026.05.16 reviced,   yo.
# 2026.05.30 reviced,   yo.
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
# githubの同じレポジトリ内にある
# セットアップマニュアル.html
# をダウンロードし、ブラウザーで開き、設定を進めてください。
# 
# 公開鍵認証の
# 以下の２ファイルを標準Webでログインして取得します。
# API用ログインidファイル:  "./.auth/e_api_authid.txt"       # ホーム > 「お客様情報」> 「設定情報」画面のAPIでダウンロードしたIDファイル。
# 秘密鍵ファイル:           "./.auth/e_api_private_key.pem"  # 顧客情報画面のAPIでダウンロードした秘密鍵ファイル。
#
# 上記ファイルを用意するための手順
# 
# 立花証券e支店API用  認証ID・秘密鍵等の取得方法
# 
# ご注意
# ・本番環境とデモ環境では、各々別の認証ID、秘密鍵、公開鍵のセットになります。
# ・デモ環境でv4r9を利用する場合、デモ環境の標準web画面にログインしていただき、
#   デモ環境専用の認証ID、秘密鍵、公開鍵のセットを取得してください。
# 
# 取得手順
# 1）パスキーを登録し、パスキーで標準webにログインします。
# 
# 2）ホーム > 「お客様情報」の画面へ移動します。
# 
# 3）ページ下の方にある「設定情報」の欄の「ｅ支店・API利用設定」の項目の「参照・設定する」のリンクをクリックします。
# 
# 4）「e支店・API利用有無（必須設定）」を「利用する」をオンにします。
# 
# 5）まず下に現れた「認証ID」の「ＤＬ」ボタンを押し、認証IDファイルをダウンロードします。
# 	認証IDファイル名: e_api_authid.txt
# 
# 6）次に認証IDの下の「公開鍵暗号化方式公開キー（必須登録）」の「登録（自動）」をオンにします。
# 
# 7）「秘密キー」の下の「登録」を押します。公開キーの作成＋登録と秘密鍵の作成が行われます。
# 
# 8）上の操作の直後に「ＤＬ」ボタンを押します。
# ＊注意：登録ボタンを押したときの画面でのみダウンロード可能になります。
# 別の画面に移動してしまうと、後から再ダウンロードすることはできません（その場合は再登録・再発行になります）。
# 
# ダウンロードされるファイル：
# e_api_authid.txt（手順5で取得。認証に必須の認証IDファイル。）
# e_api_private_key.pem （ログインで返される暗号化された仮想urlを復号する秘密鍵。）
# 	※絶対に他者に渡さないこと。
# e_api_private_key.der （同上、Windows環境での秘密鍵。）
# 	※絶対に他者に渡さないこと。
# e_api_public_key.pem （ｅ支店に登録される公開鍵。）
# 
# ※privateキーは、内容を全て理解しているプログラムでのみ使用してください。
# 安全のため、弊社提供のサンプルプログラムも例外ではありません。
# 内容を十分理解した上で実行してください。
# 
# 固定IP指定の推奨
# 秘密鍵、第2パスワードファイル、またはログインレスポンスファイルが万が一流出した場合、
# 第三者に不正ログインされるリスクがあります。
# 安全のため、接続元を固定IPに限定する設定（IP制限）を行ってのご利用を強く推奨いたします。# 
# 
# 事前準備は以上です。
# 
# 
# 
#
# == ご注意: ========================================
#   本番環境にに接続した場合、実際に市場に注文が出ます。
#   市場で約定した場合取り消せません。
# ==================================================
#
#

"""
立花証券e支店API - API接続・自動実行メインプログラム（再起動対応版）

機能: 環境変数からセキュアに復号鍵を取得して秘密鍵をメモリ上に展開し、
      APIにログインして復号済みの仮想URL（1日券）を隠しフォルダに出力します。
"""


import base64
import datetime
import json
import os
import sys
import time
import urllib.parse
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
CONFIG_FILE = "./.auth/secure_config.enc"            # 暗号化設定ファイル
FNAME_URL_INFO = "file_url_info.txt"                # API接続情報ファイル
FNAME_LOGIN_RESPONSE = "./.auth/file_login_response.txt"  # ログイン応答保存先
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
    # 日本標準時（Japan Standard Time、JST）を利用のこと。
    # システム時刻を API規定書式 "YYYY.MM.DD-hh:mm:ss.sss" の文字列に変換
    
    # 年.月.日-時:分:秒 の部分を作成
    str_date = dt_now.strftime("%Y.%m.%d-%H:%M:%S")
    
    # マイクロ秒（6桁ゼロ埋め）から先頭の3桁を切り出してミリ秒を作成
    str_micro = f"{dt_now.microsecond:06d}"
    str_ms = str_micro[0:3]
    
    # ドットで結合してAPI規定書式を完成
    return str_date + "." + str_ms


def func_replace_urlencode(str_input):
    """
    URLエンコード文字の変換
    
    入力文字列から1文字ずつ抽出し、変換対象の記号である場合は
    対応する「% + 16進数」の文字列へ手動で置き換えて結合します。
    """
    str_encode = ''
    
    # 入力された文字列から1文字ずつ順番に取り出して判定
    for i in range(len(str_input)):
        str_char = str_input[i:i+1]

        if str_char == ' ' :
            str_replace = '%20'
        elif str_char == '!' :
            str_replace = '%21'
        elif str_char == '"' :
            str_replace = '%22'
        elif str_char == '#' :
            str_replace = '%23'
        elif str_char == '$' :
            str_replace = '%24'
        elif str_char == '%' :
            str_replace = '%25'
        elif str_char == '&' :
            str_replace = '%26'
        elif str_char == "'" :
            str_replace = '%27'
        elif str_char == '(' :
            str_replace = '%28'
        elif str_char == ')' :
            str_replace = '%29'
        elif str_char == '*' :
            str_replace = '%2A'
        elif str_char == '+' :
            str_replace = '%2B'
        elif str_char == ',' :
            str_replace = '%2C'
        elif str_char == '/' :
            str_replace = '%2F'
        elif str_char == ':' :
            str_replace = '%3A'
        elif str_char == ';' :
            str_replace = '%3B'
        elif str_char == '<' :
            str_replace = '%3C'
        elif str_char == '=' :
            str_replace = '%3D'
        elif str_char == '>' :
            str_replace = '%3E'
        elif str_char == '?' :
            str_replace = '%3F'
        elif str_char == '@' :
            str_replace = '%40'
        elif str_char == '[' :
            str_replace = '%5B'
        elif str_char == ']' :
            str_replace = '%5D'
        elif str_char == '^' :
            str_replace = '%5E'
        elif str_char == '`' :
            str_replace = '%60'
        elif str_char == '{' :
            str_replace = '%7B'
        elif str_char == '|' :
            str_replace = '%7C'
        elif str_char == '}' :
            str_replace = '%7D'
        elif str_char == '~' :
            str_replace = '%7E'
        else :
            # 変換対象外の英数字などはそのまま使用
            str_replace = str_char
            
        # 変換後の文字または元の文字を後ろに結合
        str_encode = str_encode + str_replace        
        
    return str_encode


def func_read_from_file(str_fname):
    """ファイルから文字情報を一括読み込み（BOMを自動排除）"""
    str_read = ''
    try:
        # utf-8-sig を指定してBOMを自動的に排除しファイルを開く
        with open(str_fname, 'r', encoding='utf-8-sig') as fin:
            while True:
                line = fin.readline()
                if not line:
                    break
                str_read = str_read + line
        return str_read
    except IOError as e:
        print(f"[エラー] ファイルを読み込めません: {str_fname}")
        raise e


def func_write_to_file(str_fname_output, str_data):
    """ファイルに書き込み、権限を所有者のみ(600)に制限"""
    try:
        # 出力先フォルダの存在を確認し、存在しない場合は自動作成
        str_dir = os.path.dirname(str_fname_output)
        if str_dir and not os.path.exists(str_dir):
            os.makedirs(str_dir, exist_ok=True)

        # データをファイルへ書き込み
        with open(str_fname_output, 'w', encoding='utf-8') as fout:
            fout.write(str_data)
        
        # パーミッションを600（所有者のみ読み書き可能）に制限
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
    
    json_param = json.dumps(work_dic_req, indent=4, ensure_ascii=False)
    return f"{str_url}?{json_param}"


def func_api_req(str_request_method, str_url): 
    """
    APIリクエストの送信と、Shift-JIS応答のデコード（リトライ・タイムアウト対応版）
    """
    print('--- 送信電文 -------------------------------------------')
    print(str_url)

    # 接続および読み込みのタイムアウト時間を設定
    timeout_config = urllib3.Timeout(connect=API_TIMEOUT_SECONDS, read=API_TIMEOUT_SECONDS)
    http = urllib3.PoolManager()
    
    response_data = None
    status_code = None

    # 最大試行回数に達するまで通信をリトライ
    for attempt in range(1, MAX_RETRY_COUNT + 1):
        try:
            # 2回目以降の試行（再接続）の前に、指定されたインターバル時間待機
            if attempt > 1:
                print(f"[{attempt}/{MAX_RETRY_COUNT} 回目] 再接続を試みます...（{RETRY_INTERVAL_SECONDS}秒待機）")
                time.sleep(RETRY_INTERVAL_SECONDS)

            req = http.request(str_request_method, str_url, timeout=timeout_config)
            status_code = req.status
            response_data = req.data
            break  # 正常に通信できた場合はループを抜ける

        except (TimeoutError, MaxRetryError) as ce:
            print(f"\n[警告] 通信エラーが発生しました (試行: {attempt}/{MAX_RETRY_COUNT})")
            print(f"エラー詳細: {ce}")
            
            # 最大リトライ回数を超えて失敗した場合はConnectionErrorを発生
            if attempt == MAX_RETRY_COUNT:
                raise ConnectionError(
                    f"APIサーバーへの接続に規定回数失敗しました。サーバーがメンテナンス中か、停止している可能性があります。\n"
                    f"設定されたタイムアウト時間: {API_TIMEOUT_SECONDS}秒"
                )
        except Exception as ex:
            print(f"\n[警告] 予期せぬネットワーク例外が発生しました: {ex}")
            if attempt == MAX_RETRY_COUNT:
                raise ex

    print(f"HTTP Status: {status_code}")

    # 受信した電文をShift-JISからUTF-8へデコード（不正なバイトは無視）
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
    # 規定書に基づき、OAEPパディングおよび内部ハッシュSHA-256を用いて復号器を初期化
    decryptor = PKCS1_OAEP.new(private_key_obj, hashAlgo=SHA256)

    # Base64文字列の前後の引用符や空白をクレンジングしてからデコード
    clean_b64data = encoded_encrypted_sUrl.strip().replace('"', '')
    decoded_b64data = base64.b64decode(clean_b64data)
    
    # 秘密鍵で復号し、BOM対応を考慮してutf-8-sigでデコード
    decrypted_bytes = decryptor.decrypt(decoded_b64data)
    return decrypted_bytes.decode("utf-8-sig").strip()


def func_login_auth(int_p_no, class_account_property):
    """公開鍵認証（秘密鍵ログイン）リクエストの組み立てと実行"""
    str_p_sd_date = func_p_sd_date(datetime.datetime.now())

    # ログインリクエストに必要なパラメータをマッピング
    dic_req_item = {
        "p_no": str(int_p_no),
        "p_sd_date": str_p_sd_date,
        "sCLMID": "CLMAuthLoginRequest",
        "sAuthId": class_account_property.sAuthId,
        "sJsonOfmt": class_account_property.sJsonOfmt
    }
    
    str_request_method = 'POST'
    str_url = func_make_url_request_from_dic(True, class_account_property.sUrl, dic_req_item)

    str_api_response = func_api_req(str_request_method, str_url)
    return json.loads(str_api_response)


# --- メイン処理シーケンス ------------------------------------------------

def func_login(auth_id, private_key_obj):
    """ログインシーケンス全体の制御と応答の復号化保存"""
    my_account_property = ClassDefAccountProperty()

    # 接続情報の読み込みと認証用IDの設定
    func_get_url_info(FNAME_URL_INFO, my_account_property)
    my_account_property.sAuthId = func_replace_urlencode(auth_id)

    # p_noの初期化とファイル保存（ログイン時は 1 固定）
    my_login_property = ClassDefLoginProperty()
    func_save_p_no(FNAME_INFO_P_NO, my_login_property.p_no)
    
    print('\n== 立花証券API ログイン処理開始 ========================')
    dic_return = func_login_auth(my_login_property.p_no, my_account_property)
    
    # 応答結果のステータスコードを判定
    int_p_errno = int(dic_return.get('p_errno', -1))
    int_sResultCode = int(dic_return.get('sResultCode', -1))
    
    if int_p_errno == 0 and int_sResultCode == 0:
        url_request_raw = dic_return.get('sUrlRequest', '')
        if len(url_request_raw) > 0:
            print('-> ログイン成功。公開鍵暗号化された仮想URLの復号を行います...')
            
            # 各機能の暗号化された仮想URLを秘密鍵で1つずつ復号
            target_url_keys = ['sUrlRequest', 'sUrlMaster', 'sUrlPrice', 'sUrlEvent', 'sUrlEventWebSocket']
            for key in target_url_keys:
                if dic_return.get(key):
                    dic_return[key] = decrypt_sUrl(dic_return[key], private_key_obj)
            
            json_data = json.dumps(dic_return, indent=4, ensure_ascii=False)
            
            # 復号済みの応答内容を隠しディレクトリへ保存
            func_write_to_file(FNAME_LOGIN_RESPONSE, json_data)
            print(f'【成功】復号したログインレスポンスを保存しました: {FNAME_LOGIN_RESPONSE}')
            print('========================================================')
            print(f"交付書面更新予定日 (sUpdateInformWebDocument): {dic_return.get('sUpdateInformWebDocument')}")
            print(f"APIリリース予定日  (sUpdateInformAPISpecFunction): {dic_return.get('sUpdateInformAPISpecFunction')}")
            print('========================================================')
        else:
            # 契約締結前書面が未読状態の場合は処理を中断
            print('\n[警告] 契約締結前書面が未読状態です。')
            print('APIは利用できません。ブラウザから標準Web画面を開き、書面を確認してください。')
            sys.exit(1)
    else:
        # ログインエラー発生時の情報を出力
        print('\n[エラー] ログインに失敗しました。')
        print(f"p_errno: {dic_return.get('p_errno')} ({dic_return.get('p_err')})")
        print(f"sResultCode: {dic_return.get('sResultCode')} ({dic_return.get('sResultText')})")
        sys.exit(1)


def load_api_credentials():
    """環境変数および暗号化ファイルから認証に必要な情報をメモリ上に展開"""
    # 環境変数から暗号化用共通鍵を取得
    fernet_key_str = os.environ.get("API_DECRYPT_KEY")
    if not fernet_key_str:
        raise RuntimeError(
            "復号用の環境変数 'API_DECRYPT_KEY' がシステムに設定されていません。\n"
            "「セットアップマニュアル.html」の手順に沿って環境変数が正しくセットされているか確認してください。"
        )
    
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"暗号化設定ファイルが見つかりません: {CONFIG_FILE}")
    
    # 暗号化設定ファイルをバイナリモードで一括ロード
    with open(CONFIG_FILE, 'rb') as f_in:
        encrypted_bytes = f_in.read()

    # 共通鍵を用いて暗号化設定ファイルを復号
    cipher = Fernet(fernet_key_str.encode())
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    
    # 復号されたJSON文字列からアカウント設定をパース
    config = json.loads(decrypted_bytes.decode('utf-8'))
    auth_id = config["auth_id"]
    
    # 格納されているPEMテキストから秘密鍵オブジェクトをメモリ上にロード
    private_key_obj = RSA.import_key(config["private_key"])
    
    return auth_id, private_key_obj


def main():
    """プログラムのエントリポイント"""
    try:
        # メモリ上へのセキュア展開を実行
        my_auth_id, my_private_key = load_api_credentials()
        print("【セキュリティ認証】秘密鍵のメモリ展開に成功しました。")
        
        # ログインメインシーケンスの実行
        func_login(my_auth_id, my_private_key)
        
        print(f"利用中のAuthID: {my_auth_id}")
        print("API自動ログイン処理がすべて正常に完了しました。")
        
    except ConnectionError as ce:
        # 規定回数リトライをオーバーした通信例外をトラップしてメッセージを表示
        print(f"\n【通信エラーを検知しました】\n{ce}", file=sys.stderr)
        print("時間を置いて再起動するか、サーバーの稼働スケジュールを確認してください。", file=sys.stderr)
        sys.exit(1)
        
    except Exception as e:
        # その他の実行時例外をまとめて捕捉
        print(f"\n【実行エラー】API自動ログイン処理の実行に失敗しました: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
