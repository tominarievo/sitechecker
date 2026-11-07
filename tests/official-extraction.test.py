"""公式PDFの表から、誤アクセス防止の分割URLと閉鎖表示を取り込む境界を検証。"""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("extract_official", Path(__file__).parents[1] / "tools" / "extract-official.py")
extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extractor)


class Page:
    def __init__(self, plain, layout=None):
        self.plain, self.layout = plain, layout or plain

    def extract_text(self, extraction_mode=None):
        return self.layout if extraction_mode == "layout" else self.plain


class Reader:
    def __init__(self, *pages):
        self.pages = pages


class ExtractionTests(unittest.TestCase):
    def test_ccj_wrap_and_closed_site(self):
        reader = Reader(Page("掲載ウェブサイト総数：2サイト"), Page(
            "2\n取得日：2026/5/8\nShop https:// shop.exam\nple.com 商品未着 2026/6/17\n"
            "1\n更新日：2026/5/28\nBrand https://www. other.example/ 模倣品販売 2024/6/26\n",
            "サイト閉鎖\n2   Shop   https://   shop.exam\n    ple.com\n\n\n\n\n\n\n\n1   Brand   https://www. other.example/"))
        result = extractor.extract_ccj(reader)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["target"], "https://shop.example.com")
        self.assertEqual(result[0]["date"], "2026-06-17")
        self.assertEqual(result[0]["status"], "closed_by_source")
        self.assertEqual(result[1]["date"], "2024-06-26")
        self.assertEqual(result[1]["description"], "模倣品販売")
        self.assertEqual(result[1]["status"], "not_checked")

    def test_ccj_partial_parse_is_rejected(self):
        with self.assertRaises(ValueError):
            extractor.extract_ccj(Reader(Page("掲載ウェブサイト総数：45サイト")))

    def test_caa_only_named_target_table(self):
        result = extractor.extract_caa(Reader(Page(
            "令和８年８月４日\n本件偽サイトの名称 ドメイン名\nSHOP scam.example\n（注１）\n"
            "参考 https://www.caa.go.jp/ 正規店 legit.example")))
        self.assertEqual([r["target"] for r in result], ["https://scam.example"])
        self.assertEqual(result[0]["date"], "2026-08-04")

    def test_unknown_caa_format_is_rejected(self):
        with self.assertRaises(ValueError):
            extractor.extract_caa(Reader(Page("公式な注意喚起。参考: https://www.caa.go.jp/")))


if __name__ == "__main__":
    unittest.main()
