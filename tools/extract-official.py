"""指定した公式PDFの対象表だけを抽出する。Webページ中の全URLを危険リストにはしない。"""
import json
import re
import sys
from datetime import datetime
from pypdf import PdfReader


def iso(value):
    return datetime.strptime(value, "%Y/%m/%d").date().isoformat()


def extract_ccj(reader):
    text = "\n".join(page.extract_text() for page in reader.pages)
    expected = re.search(r"掲載ウェブサイト総数[：:]\s*(\d+)サイト", text)
    if not expected:
        raise ValueError("CCJ: 総件数の表記が見つかりません。PDF形式を確認してください")
    records = []
    for page in reader.pages:
        plain = page.extract_text()
        anchors = list(re.finditer(r"(?:^|\n)\s*(\d+)\s*\n\s*(?:取得日(?:時)?|更新日)[：:]", plain))
        if not anchors:
            continue
        layout = page.extract_text(extraction_mode="layout").splitlines()
        row_lines = {int(m[1]): i for i, line in enumerate(layout)
                     if (m := re.match(r"^\s*(\d+)\s{2,}", line)) and "http" in line}
        # 複数行のサイト名等でURLが次行に出る場合も、表のNo.列を使用する。
        for i, line in enumerate(layout):
            m = re.match(r"^\s*(\d+)\s{2,}", line)
            if m and int(m[1]) in [int(a[1]) for a in anchors]:
                row_lines.setdefault(int(m[1]), i)
        closed = set()
        for i, line in enumerate(layout):
            if "サイト閉鎖" in line and row_lines:
                nearest = min(row_lines, key=lambda n: abs(row_lines[n] - i))
                if abs(row_lines[nearest] - i) > 10:
                    raise ValueError("CCJ: 閉鎖表示と行の対応を確認できません")
                closed.add(nearest)
        for i, anchor in enumerate(anchors):
            chunk = plain[anchor.end():anchors[i + 1].start() if i + 1 < len(anchors) else len(plain)]
            # URLのカラムは誤アクセス防止のため分割されている。
            m = re.search(r"(https?://(?:www\.)?)\s+([a-zA-Z0-9.-]+(?:/[^\s]*)?)", chunk)
            if not m:
                raise ValueError(f"CCJ: No.{anchor[1]} のURLを抽出できません")
            target = m[1] + m[2]
            tail = chunk[m.end():]
            # 改行で折り返されたドメインの続きを結合する（同じ行の隣の列は結合しない）。
            while (cont := re.match(r"[ \t]*\n[ \t]*([a-zA-Z0-9./-]+)(?=\s|$)", tail)):
                target += cont[1]
                tail = tail[cont.end():]
            dates = re.findall(r"\b20\d{2}/\d{1,2}/\d{1,2}\b", chunk)
            category = re.search(r"商品未着|商品違い|模倣品販売", chunk)
            if not dates or not category:
                raise ValueError(f"CCJ: No.{anchor[1]} の日付・区分が不明です")
            records.append({"scope": "host", "target": target, "date": iso(dates[-1]),
                            "description": category[0], "status": "closed_by_source" if int(anchor[1]) in closed else "not_checked"})
    if len(records) != int(expected[1]):
        raise ValueError(f"CCJ: 総件数{expected[1]}と抽出件数{len(records)}が一致しません")
    return records


def extract_caa(reader):
    first = reader.pages[0].extract_text()
    start = first.find("本件偽サイトの名称 ドメイン名")
    end = first.find("（注１）", start)
    if start < 0 or end < 0:
        raise ValueError("消費者庁: 対応するドメイン表がありません。新形式は抽出処理の確認が必要です")
    date = re.search(r"令和\s*([０-９0-9]+)年\s*([０-９0-9]+)月\s*([０-９0-9]+)日", first)
    if not date:
        raise ValueError("消費者庁: 公表日が見つかりません")
    published = datetime(2018 + int(date[1]), int(date[2]), int(date[3])).date().isoformat()
    domains = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", first[start:end])
    if not domains:
        raise ValueError("消費者庁: ドメイン表が空です")
    return [{"scope": "host", "target": "https://" + host, "date": published,
             "description": "偽通販サイト", "status": "not_checked"} for host in domains]


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    records = {"ccj": extract_ccj, "caa": extract_caa}[sys.argv[1]](PdfReader(sys.argv[2]))
    print(json.dumps(records, ensure_ascii=False))
