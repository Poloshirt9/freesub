#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免费节点自动测活订阅池 v2 — 全协议 · 高精度 · 低误杀
====================================================

架构（三阶段流水线）:
  1. 抓取订阅源 → 解析全部协议 URI 为统一节点对象
     (vless/vmess/trojan/ss/hysteria2/tuic/anytls + reality + 全部传输层)
  2. 真实测活（sing-box v1.14 内核，逐节点 SOCKS 入站 + 节点出站）:
     - 阶段A 端口预检: TCP/QUIC 直连握手, 快速丢弃死端口 (削减 90% 无效工作)
     - 阶段B 真实探测: 多 URL 探测 (gstatic 204 / cloudflare trace) 
       + 经代理取真实出口 IP (api.ip.sb/geoip → 一次拿 country+asn+isp)
       + Cloudflare 限时下载测速 → 断流节点识别 (吞吐量不足)
       + cloudflare trace tls=VERIFIED → MITM/劫持节点识别
  3. 分类与导出:
     - 国家: 出口 IP ip-api.com 批量(45req/min 免费) → MaxMind GeoLite2 兜底
     - 属性: hosting=true/CDN网段/IDC ASN → 机房 | mobile=true → 移动
            | 运营商白名单+rDNS → 家宽
     - 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
"""

import os
import re
import io
import sys
import json
import time
import uuid
import base64
import shutil
import socket
import zipfile
import tarfile
import platform
import subprocess
import ipaddress
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import yaml
    import maxminddb
except ImportError as e:
    print(f"[!] 缺少依赖: {e} — 请先 pip install -r requirements.txt")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════
# 配置
# ══════════════════════════════════════════════════════════════════

SOURCE_URLS = [
    "https://peige.dpkj.qzz.io/dapei",
    "https://ghfast.top/https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://bestcf.pages.dev/random-region/TW/50.txt",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/countries/kr/mixed",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/countries/tw/mixed",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/countries/jp/mixed",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/27.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/29.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "vless://5d3cbdb2-b82d-4078-82b8-5dd413cca82b@35.229.136.113:35412?security=reality&encryption=none&pbk=eg6DfbLnWtz7PubkXRYvSuQx6QWIRxUsn4l7QEO3Cg4&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=0630b874d595#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2018
vless://5859f6a7-cda1-47c2-8353-fcdee281f31d@104.199.219.172:40800?security=reality&encryption=none&pbk=zohUbvPLKVBwzuDmZNsaXXFYZSKA9_xEhdUyURChrgo&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=186e4c2732d61a3d#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2020
vless://b0342e8a-a25e-4e30-b598-d9391b0df4c9@34.80.184.198:44848?security=reality&encryption=none&pbk=w9vWLOHjl46krA8IEpGoPI9scTL0rFdjCtjdukJDciU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=2338740580a5de#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2015
vless://41b96ee9-ee5e-455f-9753-187a9dead97a@35.221.158.209:32981?security=reality&encryption=none&pbk=JSn0GPz1WOSTUDBxN_XYnhgb2Jpjc2LpfBTzX1j3V2E&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=70f4b7a4c40636#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2012
vless://d318cdac-0033-4b6e-98bf-35116e79c93f@54.251.224.5:26017?security=reality&encryption=none&pbk=cy4ePzAdSz4pqRmAXXchMIgSoSKo8qjq2qLk5805LRA&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=af1c2e33b0c7dad7#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2039
vless://f053b140-9673-4ac5-bc8b-587bfd2c8fd8@54.255.121.205:43840?security=reality&encryption=none&pbk=tDzxVcXg6zzA1r0I_1j2y4vE0zkgmIVX3_Jf0UG1AnA&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=ac4b9f02123aa50b#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2007
vless://2a6c617d-98e4-49c3-95ab-76f02fcf0150@46.137.202.178:12512?security=reality&encryption=none&pbk=sO0RBMr_l8TLtZaYBX8n3NdI9AtaugUqJpCR1szNsyA&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=e692a8250d2e2fd0#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2020
vless://49c0aac1-5e05-4f04-b624-248fc59e03c4@54.169.200.246:41688?security=reality&encryption=none&pbk=srwIElIGTPs0kshpN1vvPsn4wixV_pLd56y_v9m0sTk&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=7f342137c20387#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2033
vless://9d9a048b-3aea-4b3e-b106-1106bf301feb@54.251.9.130:24146?security=reality&encryption=none&pbk=VeluC9A7XDurAWQNgXKShS2SJSgoK79QHFgiAMYrvGo&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=7205d9079521832c#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2061
vless://85a6bd94-83a9-4e80-849f-c06d7011d1a4@35.201.163.218:30837?security=reality&encryption=none&pbk=LXPNhrAGxr_QE4YCdJfKE40ebsPNIHnLbydhl6bipCo&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=97101ba788915e5a#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2016
vless://bf8cc771-51a0-4395-810f-1f135325cfc1@34.81.129.171:34376?security=reality&encryption=none&pbk=Atq4Fo_Mg48QtKXagBW9jnhaQSDUCiKgnATB2EU6OHU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=8dbafb690450d8a9#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2017
vless://88a67610-b7ae-42ba-8af0-29cfa54cef37@35.78.59.6:47571?security=reality&encryption=none&pbk=OyfEDzOiDM5eMvTacJ4bVhF1V0QZgvz-vP3K456l3W4&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=4c8b46e500b0f3ad#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2035
vless://871bfce7-8440-4394-8d82-56b51f20fdad@18.183.215.124:28573?security=reality&encryption=none&pbk=1DJr9toke7FRuSXjibBVuNvRnLnJnN5kXwUBG6Romzg&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=03653bc03be10c97#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2003
vless://e2b8b217-cffb-4d66-9b8b-eca6e4334032@13.231.19.51:11690?security=reality&encryption=none&pbk=Bv3z0_uFRabB9C4CFpNfqepZUyeO4YTh1duJdMBNLkg&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=034885e346fd30#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2022
vless://b969ef8f-7bdb-474f-9481-d8f3c5686fb8@13.231.7.104:24620?security=reality&encryption=none&pbk=eZthMfn0kQJFNr_srk502fr8yUHMoHQ7Oh3v4_HfTBI&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=db2cb3b3c2dbb711#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2047
vless://e8358eb5-7210-4cf8-982f-68af141b7694@56.69.159.191:53271?security=reality&encryption=none&pbk=1P58ZYmo81kPDnL4U7SnEUA-aT2R86l-o6dbFXoeDjc&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=0a9bd9db19578964#%F0%9F%87%B2%F0%9F%87%BE%20%E9%A9%AC%E6%9D%A5%E8%A5%BF%E4%BA%9A%2004
vless://3a62a0c2-ba80-43a9-b757-9aca88b0552e@104.199.134.231:28364?security=reality&encryption=none&pbk=NPhCET0GkjSZuKg4vWsPHLvjYGHW9w99Ucxvavu0-1I&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=7241c359c2dfab#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2014
vless://898537d9-ce3a-4937-bbef-c0fa61c07791@93.189.94.67:48296?security=reality&encryption=none&pbk=ga1wUMMknP4pwJfUNOOvD9I35XV4q3c73byXPYbRxBE&headerType=none&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=109657bb2dbe99#%E9%A2%91%E9%81%93%20%40pgkj666
vless://43c23116-1115-4af4-a0f0-56f02841a605@185.254.205.79:19842?security=reality&encryption=none&pbk=sfOfuQeJBlKfDnPL_EMWUxMIiFAN8BNKjtWDUvlsjzM&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=25ebc9e0a912#%F0%9F%87%AA%F0%9F%87%B8%20%E8%A5%BF%E7%8F%AD%E7%89%99%2002
vless://9fc6444b-987a-41d5-9bf5-195d147e0a05@206.251.54.34:55596?security=reality&encryption=none&pbk=QQUHUyF5Wb3XeRRrky-WOaRTxBtHokNaMec02HURWSI&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=6ac09686189038#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2001
vless://64d77a12-ad6b-4d85-a349-bd287535af1c@35.194.157.16:43450?security=reality&encryption=none&pbk=HNPJBiUbqYVC3ylvu1GA7fCHLTaHO7S13Bex1nm0O1o&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=e65d010354bdad73#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2009
vless://b0399730-1618-4727-8ddd-2baf94ab90d6@34.80.164.239:21776?security=reality&encryption=none&pbk=nm6jFiI7_auZ15UMqpeEbiITrK4OR2rfFTqXhe5pMFA&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=79b6f82800c68925#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2019
vless://83973343-90db-423d-a5f7-2e3b56aeb8f4@43.202.46.25:28482?security=reality&encryption=none&pbk=8fsYG_Pg35aeg1E5Gc3HUaXou2OUQee4ukxVk99iR0s&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=fa1e592603c283#%E4%B8%8D%E5%AE%9A%E6%97%B6%E6%9B%B4%E6%96%B0%20%20%E9%98%B2%E5%A4%B1%E8%81%94%E5%A4%87%E7%94%A8%20%20
vless://78990f64-7bc8-48b9-a127-0d5545593a38@43.203.242.114:12359?security=reality&encryption=none&pbk=8SUi1EG0YaPd7spjghl2QcZYvuJfEtPjqR9Vpzgc2Q4&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=8f30f2fa8282cebc#%E4%BA%A4%E6%B5%81%E7%BE%A4%20%40pgkj0402
socks://ODg4ODo4ODg4@8.210.31.250:1080#%E9%A6%99%E6%B8%AF
vless://bd2bf46b-52c7-499a-9f61-9f06235063dc@35.236.136.126:21308?security=reality&encryption=none&pbk=ixmcbiPqv1AXx4C1bYiAX89D5qQhCSn70IgfSsCbiF4&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=8f0cae5b716ef2#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2010
vless://7b15ec5b-8aea-4742-963e-78b18363c2d4@104.155.197.135:12069?security=reality&encryption=none&pbk=KrOnvDlG7ZH3x6uwWqfhnyIr-L8yjCtLm9MBkQCuJCw&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=a4ccdd0ffbb8ab3f#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2011
vless://b64d2f40-c46d-4997-98cd-80ef30fe92e0@34.80.191.169:35155?security=reality&encryption=none&pbk=ovrSiv4IO8ANPEwSpuJFNp266_vqTC8tRZ14A3uiUgo&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=711830eff59f40#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2013
vless://0fada528-59c7-44b7-a3d7-377c36c55d97@35.229.131.182:47394?security=reality&encryption=none&pbk=yrZ6uI4z0IVUK3s_FJxIhEfLofvK9PwxT0HcSj_ljmQ&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=8ecbc93134b311#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2007
vless://3fd01721-c3e7-4205-9b2c-4eb1f8f8578d@18.178.233.232:16138?security=reality&encryption=none&pbk=WVECuhHY1uql8Rwwmo10t72L1s_l-03b23w0gY2PDkI&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=6305d3c1a69dc2#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2029
vless://926912d3-1656-4e83-9971-411b283f7998@13.114.124.85:18614?security=reality&encryption=none&pbk=w0jjW_RLHvQc2tk_7sbxfBawdMlJZfb7rKROwg051gA&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=c6966bed91ecd9#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2002
vless://37c00ed0-de07-4c7d-a4cf-049805c98713@35.77.87.249:42263?security=reality&encryption=none&pbk=lLbzgXK1hx6K2J6rDUARlzZzjWqVXMjIhHsKmgEQI0U&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=d5cd4778d2da33#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2033
vless://a5e21cfd-c5a1-46b0-8697-f284585b9327@3.112.131.162:40319?security=reality&encryption=none&pbk=_e5fM6ugSlhDfT2bKW1QaNtMagHIRcah9giIJJn7D2g&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=9bdea8e40dba4c#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2005
vless://059fbe5b-21dc-413f-8f5c-dac39201914c@13.114.89.187:16611?security=reality&encryption=none&pbk=cDzA5Efsd52LehcCFXh9bS3eCuj7HQZwau-yjPqLPgQ&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=701b0c5c9dee514d#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2008
vless://f6ee4e1e-651e-47b4-8042-c037e79e48a9@13.231.156.101:14741?security=reality&encryption=none&pbk=SWkx57jwv301bXshQOVAVPjWPELg0zhSB6pGWkq7RlA&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=e09096b6b8c67707#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2040
vless://70baf116-c56f-4bb8-bf48-d1f835814a89@52.195.209.55:39512?security=reality&encryption=none&pbk=JuWGiLt32IXY1GWi0BvhbPC4y2_aId6agnJLVzHVx30&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=549d3e0c2539d5#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2016
vless://babf64f8-f9ee-4564-a097-16433f2ebd46@13.230.66.70:23607?security=reality&encryption=none&pbk=liATkHCbR_IPjdgOhHK5nZO6fgCO091bTab3v2G8Lm4&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=701b0c5c9dee514d#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2009
vless://15836880-212b-4690-b29c-1889a749bf72@43.207.162.145:32913?security=reality&encryption=none&pbk=iJhoNzfiPiua04PL88iAAyZz2u39su4ChSCiGVoekRQ&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=a8f0a95931a52732#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2048
vless://eddee2c9-fdf9-4b55-b8ac-3481a680b060@52.194.245.53:33486?security=reality&encryption=none&pbk=0XefSfdaAV77RBJrVSVBIdRNUHUlaMGmFT5mX_Aw6G8&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=1671781f157ac27e#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2050
vless://519a17ff-05a3-4488-8fd8-47cf13d1310c@52.193.64.73:33528?security=reality&encryption=none&pbk=cs0Gy8Yp-GWHukLSkeq-P08qydj71eWPBinBIxm2bWU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=adcde615c1dd88b7#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2007
vless://5b314c69-b427-4648-a8aa-6c38bc87fdc7@18.136.125.3:54618?security=reality&encryption=none&pbk=BugMYB6c9k66FOr1dTMnkojMXH5OCYP2wDH2nntWGgk&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=93ed34c8eea01f#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2014
vless://cb51e964-70a5-4522-9d04-d97b58fe509a@56.68.93.171:59463?security=reality&encryption=none&pbk=GNLuMPdi52lBbZ_9tz3nWOcKdQYVr4lzE4RX0tKQAEo&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=2f92a5b7373b593c#%F0%9F%87%B2%F0%9F%87%BE%20%E9%A9%AC%E6%9D%A5%E8%A5%BF%E4%BA%9A%2002
vless://44aedcca-28f8-411d-bed2-9bd6aa491cb5@54.151.153.129:59180?security=reality&encryption=none&pbk=NntGU23khU2ASY2g1XM5_Vl0G39MyoXre5q7vanorDM&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=3ced8a51ce74468c#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2008
vless://b0358515-1b47-4f4d-a9d8-1f0c679a4bef@54.255.0.60:20731?security=reality&encryption=none&pbk=B6s6xiBN3mXIA6JK3dHrJP460tnFcehNm3fwCKMS1W4&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=5034d2ebbe2f02#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2041
vless://2a4a8c73-681c-4c1a-b0c7-f3117f572c59@54.169.169.217:19149?security=reality&encryption=none&pbk=Q1R0MnoUXL6BBckmMtWBXuufndtVTfgookn6U-f9llk&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=bbe1a6a823bb9f6e#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2005
vless://a965aaba-e7d0-44fc-84ad-cd7c341249aa@56.10.83.247:26146?security=reality&encryption=none&pbk=4cD2BKaVODTdo4soH4gLcB7Yj-hdLDKDhvbSNQgZLEM&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=3ced8a51ce74468c#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2013
vless://d7baca0b-1255-4c1c-9fed-f615a059c9d5@52.76.84.249:12804?security=reality&encryption=none&pbk=2My5Uzi0wB4_xTFXMp1enW_lT_7LUuqUr1xp34154zw&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=b94c29d75478a981#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2004
vless://2b332aea-d02d-4fb7-9475-8ac2fe83a33d@54.255.30.106:31252?security=reality&encryption=none&pbk=N9BE-BzVBgMhfw-78CiyP1FzJSWDf1PaOWAcAg26GyM&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=7b29146e2d4fea61#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2043
vless://7c36417c-be20-49c5-910e-23f759de1bc9@54.169.160.148:41402?security=reality&encryption=none&pbk=01tt0RH0sSR4OAdW3C5vl9dR0kzXp4tq3tr7u26_LA0&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=9309ca4c8ce50673#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2003
vless://fe113f0b-43fa-4662-9403-9f91b53fed1f@54.249.200.131:18921?security=reality&encryption=none&pbk=Ct9tvt4V8JSZ7uCbKWKuXNMG5Q7U_FMDWPHgi4YHAXw&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=2e23c31063fcff#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2017
vless://302debe4-0cc7-48d1-9433-3242dbb6730a@52.77.240.16:15562?security=reality&encryption=none&pbk=TzY8IrCzcw3jLJa9tiYLbvHb0h7L6MSZXl6JsqkDCxw&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=5ba824948be6#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2049
vless://aa6a79ea-3682-4e0e-bc46-af34ba6e1a6d@54.254.224.201:37249?security=reality&encryption=none&pbk=sJq1fN0yce_dC5vA2F3GPZVJ_7PxHlClAvWBwkhtWGU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=c919090e3c660c#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2021
vless://6b9f1019-d700-434e-adad-437fb3ad81da@54.238.241.88:22536?security=reality&encryption=none&pbk=hd3qje4UtfiFnCxsD7VKCLB3ArNR5zRjkwk2MTzP3WU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=4c8b46e500b0f3ad#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2034
vless://50641912-a16b-4ac3-aa2f-312c88b617e1@13.230.222.139:18384?security=reality&encryption=none&pbk=cRwzK1c65HdBluJqM3GS8YN4N-TqTCmI6X_3eEgAVms&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=3f316a236d64c1#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2026
vless://60bf43f0-dc41-42ac-8e2b-e64b73688ed2@52.199.9.165:15147?security=reality&encryption=none&pbk=1qBD5uOyQZ4Pj7UMgw9Fuyo7oZ8ruACjWOTwSl4sbA4&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=91a8f64c584660c5#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2051
vless://85dd8227-0f12-4826-a712-6313211774b5@43.217.16.8:21874?security=reality&encryption=none&pbk=75sTDYJk8ylA97-aBhAlF1tU4OaCfdOaOSIBshPW7Bs&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=42e853a5559e1032#%F0%9F%87%B2%F0%9F%87%BE%20%E9%A9%AC%E6%9D%A5%E8%A5%BF%E4%BA%9A%2003
vless://a292d697-5249-417f-aa8a-b853fa6ff35c@43.217.83.128:22012?security=reality&encryption=none&pbk=uSrE0JjmM3fOdPaVIqOdttSJXVHwgVOD0WbyeN1RCBQ&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=6d62b7e1ed6f2aed#%F0%9F%87%B2%F0%9F%87%BE%20%E9%A9%AC%E6%9D%A5%E8%A5%BF%E4%BA%9A%2006
vless://5bf65fa6-d8af-4932-970e-a13d444a24af@13.114.63.132:32652?security=reality&encryption=none&pbk=6OOibzbkPmuVsl6LgqgUJ0FLHNEqt4VYSzqygL1GL2w&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=b5c421053ba4#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2036
vless://5f1728cb-8678-44fc-8b06-5f64659d2f5a@47.130.167.253:35921?security=reality&encryption=none&pbk=G18SaAQR1NQqmi4ITcYYITGom67q6S3JD8hQTifAPwY&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=29400ecf83e074#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2029
vless://2f790dfd-d1fd-4f77-a494-6d75798135b5@52.77.187.151:25066?security=reality&encryption=none&pbk=AU-qWQ9Vs1RXJfY9UawaDULc9LsxuinVJe8hNsyPezQ&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=ac4b9f02123aa50b#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2042
vless://5e4c4ee0-9a52-421e-8427-7ad6ff027312@13.212.143.2:18516?security=reality&encryption=none&pbk=0nAOIGPKjVAgGpN_FrdSQ1qg_J-nuIhS9-UZYLMfy2g&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=6ce3397cbd5ada#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2026
vless://a2428d88-0d96-4109-abbb-e1904bc4890e@122.248.203.37:51382?security=reality&encryption=none&pbk=hPOkfyi6Ck1euOqdlX0WCQpMfooi0TWYiydeGQkR3x8&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=e692a8250d2e2fd0#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2027
vless://81853004-816d-40c1-973f-2be269ba8051@54.254.51.144:52457?security=reality&encryption=none&pbk=nA2aGvkk6Wf3NvrKavmZg_g01xujyrYAiCJS4x0kFHc&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=93ed34c8eea01f#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2019
vless://e77f740b-609e-41e0-86e7-14881c1185ea@54.169.168.70:12346?security=reality&encryption=none&pbk=8CbVZ66WQw2bBVlxbQuCZu9WmbFcxzY6nNSz1JcQZkE&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=a739eb7afcffa605#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2057
vless://bbb7de25-ba85-4bf8-aae4-07402f5a8ff4@52.196.75.65:23252?security=reality&encryption=none&pbk=fkFnev1VOzEKvHo0SXtxtS8ryGGRf0JvXjJl0_x8-xc&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=244a0bb5457ef9#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2025
vless://3bd62f91-36cd-4fb9-8051-73fa853db876@47.129.168.63:18603?security=reality&encryption=none&pbk=64nJBcA6S0_i4HtrvdQo9zr1qa1Ob_s0kJbjaJzdVBc&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=80f7b6ff44cb5246#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2031
vless://3b733177-14f5-49d5-91e6-4dce73c038e3@47.131.211.4:33164?security=reality&encryption=none&pbk=Faf18bd52wn8u9_ZGjBvfW4hkzcMhhfZhc1giF8R4G8&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=83905567c94f6679#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2015
vless://956e22b4-2257-4251-a708-679e0518e374@54.254.182.69:44416?security=reality&encryption=none&pbk=l0ERIlwtRtgldh9Kdles1rZrL3hKfityyhyu5U0Y6kM&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=29400ecf83e074#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2022
vless://8abb4009-5efe-4d27-aa56-d50c37d2b1b8@52.221.220.242:22872?security=reality&encryption=none&pbk=RSikfX950b5w04iH_VvXYAkC5zku5qilSsSIJoXzyhc&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=2798448b96fff0e0#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2050
vless://a2d84cff-5a0f-4559-b793-355d363a4738@13.212.45.128:12322?security=reality&encryption=none&pbk=AG7GDrwsSNOf3mXfGVRSKBwszQFJ_QDxqQPHlyN-HAw&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=5b89483cf98148#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2060
vless://f88db45e-4178-4545-91b5-5374d676bfbb@18.143.93.179:39254?security=reality&encryption=none&pbk=c04tnfk5tdZXpUqqlOUUsu4Pf8tzYcNUsQ0OHFcQj1k&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=7f342137c20387#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2032
vless://9e53f46e-bf21-41c7-8398-45e9edf7f12d@54.251.59.156:40785?security=reality&encryption=none&pbk=H8kaNeWDOCEsXdWBLDIZVCrp0Mqq2vjfFq1w3JmaWUg&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=ef95bddb7c6ba8#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2006
vless://7caf75cd-43e2-4d90-9df1-de2396875b3f@43.217.131.214:34581?security=reality&encryption=none&pbk=DzJipJKxpMfjwDmcs2YxsQ56EAwp0PgmYjdqwlMgDBQ&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=b7e1be34c9975c6e#%F0%9F%87%B2%F0%9F%87%BE%20%E9%A9%AC%E6%9D%A5%E8%A5%BF%E4%BA%9A%2005
vless://dc513ed7-87d0-4309-947a-30b3f89a51c6@47.128.81.182:20859?security=reality&encryption=none&pbk=y1neNdTfDZJDNmNAsexkDXyd8plDxbRr7TH5RBiAJA8&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amazon.com&sid=cc7a57d36b14c736#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2023
vless://620ca966-d78b-4c88-a5c9-acf13c7d252f@3.112.131.211:48086?security=reality&encryption=none&pbk=qq9vUmReS92PojPLpSyUY_c6CydUUtut7ffxc3V0LTo&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=7083d685446ce576#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2046
vless://0803fc94-25f9-42db-9e6b-dd1418ae50ec@47.129.185.35:49805?security=reality&encryption=none&pbk=KhyeJbZtFAik5Mx1K_AQMIEK_MPwQnwUwSe-jTjq8yU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=4a753538b6a9eee9#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2045
vless://14155d8d-14f7-4105-984b-f477e3880943@104.105.202.38:29239?security=reality&encryption=none&pbk=KGI60DoZFcBFTq4yrjFE5C4QitMypVH4HJlkM9VqB1M&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=fd7069bcd5853169#%F0%9F%87%AB%F0%9F%87%B7%20%E6%B3%95%E5%9B%BD%2001
vless://c3e2c992-6721-443f-a051-331cb8a29fad@13.229.47.178:20414?security=reality&encryption=none&pbk=H4ZErlTUck4uQYnxtURj9aHLVXQIUHIPMI8dBz7wMVg&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=ed2cfa4d6d47e0#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2046
vless://dd7429eb-b77b-4a8d-be86-c34cac86faf7@185.253.152.198:34710?security=reality&encryption=none&pbk=MXOVePed0T2SVOfYSEtecn2yApnsVC12dJ6nkujWTVU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=14b0eb7919eb7d#%F0%9F%87%AA%F0%9F%87%B8%20%E8%A5%BF%E7%8F%AD%E7%89%99%2001
vless://10dd7b2d-eda2-4a47-9f6e-5093a3cd7ded@3.38.1.152:19179?security=reality&encryption=none&pbk=BabvzCKB_cqCz56qFQhOWIypFKFhEWo9Eyn_JPZIAxA&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=fa1e592603c283#%F0%9F%8F%B3%20%E6%9C%AA%E7%9F%A5%2004
vless://32d1be4e-5094-4881-984f-f927e9961edb@13.212.253.233:41077?security=reality&encryption=none&pbk=dd41CxgkW8Nzb4424-YNVaVkody-X9xAY30bUOjEohI&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=3f7addb532645b1c#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2051
vless://37834c00-7fa5-46ba-a4b9-7e13c8fcdf8f@13.212.10.131:30666?security=reality&encryption=none&pbk=3fKobetnIIC1NFGtQEPkBx75UdTMmq886OAr9bOt2S4&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=c919090e3c660c#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2028
vless://3317270c-c577-4803-9c28-011152223f79@54.250.13.242:18538?security=reality&encryption=none&pbk=zBZDFZ2P54fpr1-tl51jN4ZyBCrEJ0syOna-KJXZ3h4&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=d5cd4778d2da33#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2032
vless://7460547d-e83c-4843-b404-9142b22261a7@3.112.47.207:29860?security=reality&encryption=none&pbk=g7I81MzpM7J6K9WLbZdaMPS9We6GYeeNY3EKRvyiKW4&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=c992a34f288be189#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2019
vless://65166c4d-a46c-40f9-83cb-ee599f5279cb@13.214.194.139:25193?security=reality&encryption=none&pbk=Qsm5dVTgDmOCvRwi8M_WVE8EmeK6Ot9i-XIfCmM1zGg&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=702186e48d5646#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2035
vless://9dd2707c-94bd-4d12-abf4-af68585c0096@13.231.220.17:41764?security=reality&encryption=none&pbk=wHjEYalfLgL38ZNZoV2FiGkNvcFpXBqSCmoq09p0sDI&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=105c434a964b2e87#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2023
vless://caaa44ad-b3d5-4f55-9507-5b57942f6922@13.231.69.194:35229?security=reality&encryption=none&pbk=JKEgmSckzu3wmGo2_wl8Xij0-PsE8QOvrEO6jS8IfFY&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=0056222303#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2054
vless://a205aa45-9314-43c6-ab0f-8718c573ee78@54.254.241.82:53836?security=reality&encryption=none&pbk=zKRmiqB6phUSq8EO4PIujKNHeNZP3JVWLwCKX8iKgVA&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=89dd6fba1e43#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2048
vless://abdb9efb-a552-4b12-bd95-e56f4820fed8@13.112.217.203:18732?security=reality&encryption=none&pbk=lsp2a_PzZnzFtikI5FMkSYh3kpTewVNgU6A0VSZCJUI&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=7946e1980d32555c#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2037
vless://4f9874e5-a8a8-4760-ba1b-ce6822b0ff19@13.212.142.27:20220?security=reality&encryption=none&pbk=nl2opNfmUuvzNzz24jEII4irqeP8xwXJufLPj4RY4Qw&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=33bc05afd35b2b#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2054
vless://4cda6bad-ae8a-4e96-8a8b-e7e675de626d@47.131.143.204:50334?security=reality&encryption=none&pbk=LlN9ORcAo_2zQnfRCfUXZPesvZt2I0BYVz7cABPAIlk&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=425fc4a18db86f#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2009
vless://e0e09114-371e-4d87-b2f0-d7ee58be74a9@3.1.248.148:54489?security=reality&encryption=none&pbk=b8P0DSI3bftNNT3I9QN_BDSdJ6RT8_aNXDcwwhelnzk&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=cc7a57d36b14c736#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2024
vless://3298044a-024f-4b48-a598-ba56c75e99f3@13.231.129.39:29224?security=reality&encryption=none&pbk=HqLe_f1G54_pDZGbCnermTm-vqDiNp6cXVMaasg3NWE&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=fcbdd08920d4c8#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2031
vless://9f752e03-411f-4df4-841f-a23c4c43d183@13.212.211.73:20221?security=reality&encryption=none&pbk=Fd3DtGiQyvw9IBKoMqKtgaKVkdvjnaErL_1ib-zXqxY&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=85ae3d83d037b7#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2055
vless://572782aa-48eb-42f1-b164-8c1e2381cf9c@35.221.252.60:50665?security=reality&encryption=none&pbk=2d8lBXxyxrcHKjy3NLycQBgkstKpHwgont5rD9hUvAQ&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=a700726f35329a4e#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2008
vless://cc138c2d-5e03-4efd-a935-fc500e938033@47.129.200.244:41159?security=reality&encryption=none&pbk=dp_CXcMGxttv9CdCq3LI7UkaHbpV9yoPKpgAGH177WY&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=41c5dc0928f602ab#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2056
vless://3e43ab01-5397-483c-a2c2-c97a6a0e5d62@18.143.103.4:33709?security=reality&encryption=none&pbk=GftgnXZMV9LhYn39z4aysGi7QtYCbyqIwqIilpbFCTM&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=82b2b5c9010b87#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2062
vless://8d644890-a8cd-46e5-a318-f2e64cce7a60@57.180.21.90:32114?security=reality&encryption=none&pbk=zsxQcqhGeGLxY7Y8PYZ0LyYvD3lJgRYd8FHp3WI9mSU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=9bdea8e40dba4c#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2006
vless://31d84170-673e-4653-afaf-0656656be6dc@52.68.64.80:25892?security=reality&encryption=none&pbk=20EMD5w9RCv9W_MtV6PfJAcKwSUpRfdQ_uA_UBHggRE&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=9b0f012413fd#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2015
vless://440ffeb3-72ce-4301-8039-2bfc329c460b@35.72.188.24:41773?security=reality&encryption=none&pbk=46x-QHcmrMdu5VknsdR_1-lMLxRmgZQkmcjN6ziTRjs&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=c9f30034dc2cc665#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2030
vless://40a726db-6815-44de-9c2f-80e7bfb8f81c@54.95.137.141:27898?security=reality&encryption=none&pbk=Pd8NKW1KgKjHl6lzGTB3qIAThLbT7alN_I1uIbAQrxA&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=9e638ff3d3d9265c#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2053
vless://3927f763-dc90-4053-a912-318de0dc6c03@52.197.69.21:16205?security=reality&encryption=none&pbk=antFLxN2FVR4W3xuriF20IyIy78Njg4W65kqlSxDqDg&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=98697585244e#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2004
vless://b0706a50-eef2-4e24-a6ff-d5b6f4caa6a2@47.131.253.190:11380?security=reality&encryption=none&pbk=bzaY4qrM0s4IwkWQDuTejvp_bohgLUntQHykOVA62lU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=3f481ad0d48d#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2040
vless://0faaa1ee-f3d2-49ec-92af-3228329f3000@172.237.44.80:19567?security=reality&encryption=none&pbk=tzm4xWHOerooioq4QQkI7VCvIapECgody_vJGDzX3UI&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=87714fc3c52a#%F0%9F%87%AE%F0%9F%87%B3%20%E5%8D%B0%E5%BA%A6%2001
vless://f7d1b40f-c424-47be-809e-9d4e75a1b993@47.128.228.95:20069?security=reality&encryption=none&pbk=WQqtqcKk5OtpVZ6U5Vw310lp04erERuDIMoqBfpsaB0&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=f1852e7b73c019fe#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2030
vless://0a6c8184-d202-41b2-acdb-1a95df2f74d3@47.129.144.8:39742?security=reality&encryption=none&pbk=x3V96vwq7lqcF47qYpDMgnxoAbERJp8Z_fna48bxYnM&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=90652b9b58bee5#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2058
vless://72de2254-547a-4b82-8006-bc72e6d7abcc@35.79.56.221:46753?security=reality&encryption=none&pbk=2McJ3AOyFVxGTNF-1xnEupfSE-VXx6hE2cTISFbZFxo&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=b9eda5ff206920ed#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2028
vless://66f9ea74-295d-425c-af01-331161bae8d9@18.179.7.11:23082?security=reality&encryption=none&pbk=lbFqrC1Be1nP6BceqztrFDBENdxyQzAdjj_bOmZB8nc&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=e064889ce12c46f0#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2043
vless://ea3fb423-d86c-461a-9610-cbad189253e2@13.230.140.251:58573?security=reality&encryption=none&pbk=P_qGsMinT163P1KLO6LzedQXEeHimWQ1CrqM4cYkFB8&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=4de17b381e6af2#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2049
vless://65ed7834-1996-47b7-839c-35d9fea3e2d9@13.113.18.50:36582?security=reality&encryption=none&pbk=RtL82236ddBzL8AmLGtUV6uOOB-g8AZ8IQMQY191Mlc&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=adcde615c1dd88b7#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2011
vless://66f5d633-c366-4af7-99fe-a0dd8d508a1e@57.180.43.113:22467?security=reality&encryption=none&pbk=lW1DMMctDff027HnUV8974xKvXTLA81CgXUQtiSIRhY&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=a52a5b7c1eec1b29#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2013
vless://7e684409-9d30-402a-a084-2f5417fd53f6@52.195.12.44:18442?security=reality&encryption=none&pbk=gX8O1ZEjAMmQwaQAe8nJbeLjb2FuB_xYB6GUpGv6eng&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=36cd768dea0661#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2021
vless://e5a9a8be-886e-4522-b11d-3edde88c9c8c@3.113.9.16:48203?security=reality&encryption=none&pbk=nxC5EiVCdXMnvfRa1LoNUs21ZNS2DdP36gfHayvUXRU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=5b63c338f69077#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2039
vless://fe855f99-4eb5-4a80-ad48-354649ff1305@52.194.211.43:56449?security=reality&encryption=none&pbk=anIR48iTD0Inl1z85396AwMvDhcx9y25DdFsVR896DE&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=25a9435577670327#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2041
vless://7ad407b1-b8f3-4591-ae75-05cf4035e09e@3.112.129.179:36024?security=reality&encryption=none&pbk=z1IzZjwLcymnYShSSGE6NkK10-S6aIGbe1_qQotmplU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=d1d28c01d2c3c6#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2045
vless://75f0b53b-ff3b-483a-b25e-5269b0229d14@13.113.195.74:14422?security=reality&encryption=none&pbk=WA02heAP6997PPTwF6hbbFXwbYmXRz1bH2ZXWk6ipEw&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=9b0f012413fd#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2010
vless://0346a35f-8e11-4b33-852d-00fa9c642878@18.177.61.231:30203?security=reality&encryption=none&pbk=dsJ2WwzENgTAgd8okJPXLpwzdsDjU67mBEnhUhgvvTk&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=40150721499a92#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2020
vless://f485492b-2c69-4334-b193-403b1e4ec1a4@13.193.9.59:31497?security=reality&encryption=none&pbk=UsFXvqh6G4IrPRVWtUUFvZUYHbV8facFnRyAl1vrbUY&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=5b63c338f69077#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2038
vless://b76630cc-5b12-4a76-8a1a-a7097f4a0e30@35.229.150.105:29465?security=reality&encryption=none&pbk=kKqDTc16crLdoQHb4X13-rUHEc83bY7eWtn1kwAaqSE&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=74f639401060da1f#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2005
vless://97e46b0b-d27c-4e94-aa00-034e29acd046@35.236.181.11:35190?security=reality&encryption=none&pbk=5v2iiibdxSDD2c7acIZ93kROtWHBTNTe0ea5EEMUHRk&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=0296fcb7c578#%F0%9F%87%B9%F0%9F%87%BC%20%E5%8F%B0%E6%B9%BE%2006
vless://a8eced73-0dbf-4312-90b8-551641a0f4d2@57.181.72.81:24406?security=reality&encryption=none&pbk=CGn1d1G4oSLsdSzF6mKV8EDzB5n4QOzB-Xe_OpKW8G0&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=a52a5b7c1eec1b29#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2018
vless://d6112c2b-b961-4850-826e-d30cb0f0c9d5@3.0.116.103:55011?security=reality&encryption=none&pbk=oQEJKlraquZ7I7sJaaOnNB72RJxDkXcw9geP9PgGtGc&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.tesla.com&sid=816de7fe3de8b0#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2018
vless://ffbc5924-65f9-45b5-9089-5bc5b2048823@52.195.111.107:49032?security=reality&encryption=none&pbk=dzdupl2cvM0mpe_hVDDBshTivuX0bOY-3QbavnoorV0&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=36cd768dea0661#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2024
vless://fa0286aa-e023-4f20-b634-e61e1e8c32aa@43.206.235.72:15476?security=reality&encryption=none&pbk=PxNPEPC__Sfi1XH112Dj3H5kvFJZr3ckhi6oRwr4TmU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=db1331e5c9c3f0#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2042
vless://cb3c9f84-903b-4701-9107-701b6347b0aa@56.69.197.40:22732?security=reality&encryption=none&pbk=vHWs24ZHKIvNpToXCwB68TK0mybgKe1Yfq1Jdnas5TU&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=2a2aa1d1366cef#%F0%9F%87%B2%F0%9F%87%BE%20%E9%A9%AC%E6%9D%A5%E8%A5%BF%E4%BA%9A%2001
vless://d64d6845-5da0-42b7-b81e-8263ca49a9d8@122.248.209.131:25436?security=reality&encryption=none&pbk=pDVraOonSeo3sj5G-Mw969DEc854v0Bpygh1N2xzFT0&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.sony.com&sid=cb344f105044fc#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2036
vless://127f98dc-cc3a-48d4-8224-9a9c80e13d5e@47.128.248.109:20440?security=reality&encryption=none&pbk=gt0qpR8MQY1hrYZDmHwtMcESvcDbFWtjKirUqSCoUwA&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=816de7fe3de8b0#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2016
vless://dd28ba19-c082-4472-96d8-a5c03d9cbacb@13.213.249.57:52786?security=reality&encryption=none&pbk=fBqmk4loQ6gWLiRk5NpwoRnAGl55PDr66fWEpkNM6Hs&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.nvidia.com&sid=cb344f105044fc#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2037
vless://6019d1ee-5fcf-4ce4-b5cb-e47fd3c29b2a@47.129.152.58:39960?security=reality&encryption=none&pbk=epKJ_k5Dc4ywEPSIIXhk27GBrJlcAJWO5kLJaOyaLTQ&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=f98458f4235fd5e3#%F0%9F%87%B8%F0%9F%87%AC%20%E6%96%B0%E5%8A%A0%E5%9D%A1%2017
vless://2c178adb-54c2-4eaa-8e30-1322d17922c4@54.178.54.169:59497?security=reality&encryption=none&pbk=l7ImR_EgkkLJ4BkITf0eHQcOazxENAz4EL8pQ1k5lko&headerType=none&fp=firefox&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=www.amd.com&sid=d1d28c01d2c3c6#%F0%9F%87%AF%F0%9F%87%B5%20%E6%97%A5%E6%9C%AC%2044
",
]

OUTPUT_DIR = "output"
COUNTRY_DIR = os.path.join(OUTPUT_DIR, "by-country")
RESIDENTIAL_COUNTRY_DIR = os.path.join(OUTPUT_DIR, "residential-by-country")

SINGBOX_VERSION = "v1.14.0"
WORKDIR = os.path.dirname(os.path.abspath(__file__))          # scripts/
BASEDIR = os.path.dirname(WORKDIR)                              # repo root
RUNTIME_DIR = os.path.join(BASEDIR, "runtime")                  # kernels & db
SINGBOX_BIN = os.path.join(RUNTIME_DIR, "sing-box")

# --- 测活阈值 (毫秒/秒) ---
# ★ 分层超时: 首击宽 (12s 容慢节点), 重试窄 (4s 快速放弃死节点)
#   依据 CI 实测: 25 分钟里 ~60% 时间烧在死节点 3×12s 满额重试上
PROBE_TIMEOUT          = 12      # 活性首击超时 (秒) — 容纳慢启动节点
PROBE_RETRY_TIMEOUT    = 4       # 活性重试超时 (秒) — 死节点快速放弃
PORT_KNOCK_TIMEOUT     = 2.5     # 端口预检超时
IP_ECHO_TIMEOUT        = 6.0     # 出口 IP 检测超时
SPEED_TEST_BYTES       = 2_500_000   # 2.5MB 下载测速 (2.5MB 足以算准吞吐且 < 70KB/s 判定线不变)
SPEED_TEST_BUDGET      = 5.0         # 测速时间预算 (秒) — 2.5MB@70KB/s=36s 必断流, 5s 预算足够判型
SPEED_MIN_BYTES_PER_S  = 70_000      # 吞吐 < 70KB/s 判定断流/不可用 (标准不变)
IP_ECHO_URLS = [                    # 经代理获取出口 IP (多路冗余)
    "https://api.ip.sb/geoip",                         # JSON: country_code/asn/isp
    "https://ipinfo.io/json",                          # JSON: country/org
    "http://ip-api.com/json/?fields=status,query,countryCode,isp,org,as",  # HTTP free
]
LIVENESS_URLS = [                    # 活性探测 URL (全部要求代理链路完整)
    "https://www.gstatic.com/generate_204",       # 实测 204 OK
    "https://www.google.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
]
SPEED_TEST_URLS = [               # 测速端点多路 (实测部分节点商屏蔽 speed.cloudflare.com)
    "https://speed.cloudflare.com/__down?bytes=" + str(SPEED_TEST_BYTES),
    "https://cachefly.cachefly.net/10mb.test",
]
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"      # warp=on 检测套壳节点
MAX_WORKERS_TEST    = 48            # 同时 sing-box 实测节点数 (Azure 2C7G 实测 24→48 稳定; sing-box 单实例 < 30MB)
MAX_WORKERS_FETCH   = 8
MAX_WORKERS_CLASSIFY = 32

# ip-api.com 免费批量: 15 req/min, 每 req ≤100 IP (仅 HTTP)
IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
IP_API_BATCH_SIZE = 100
IP_API_BATCH_RPS_INTERVAL = 4.2     # 60/15s ≈ 每 4.2s 一批

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

# ══════════════════════════════════════════════════════════════════
# 出口 IP 情报 (本地离线兜底)
# ══════════════════════════════════════════════════════════════════

# Cloudflare 官方 Anycast 全网段 (命中即 CDN 任播, 绝非家宽)
CLOUDFLARE_IP_NETWORKS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
)]

# Google / Fastly / Akamai 等常见 CDN 与云入口段 (命中即标 CDN/机房)
CDN_IP_NETWORKS_EXTRA = [ipaddress.ip_network(n) for n in (
    # Google
    "8.8.4.0/24","8.8.8.0/24","8.34.208.0/20","8.35.192.0/20","34.64.0.0/10","35.184.0.0/13",
    "35.192.0.0/14","35.196.0.0/15","35.200.0.0/13","35.216.0.0/15","35.220.0.0/14",
    "64.15.112.0/20","64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","72.14.192.0/18",
    "74.125.0.0/16","108.177.0.0/17","142.250.0.0/15","172.217.0.0/16","173.194.0.0/16",
    "209.85.128.0/17","216.58.192.0/19","216.239.32.0/19",
    # Fastly
    "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23",
    "104.156.80.0/20","140.248.64.0/18","146.75.0.0/16","151.101.0.0/16",
    "157.52.64.0/18","167.82.0.0/17","199.232.0.0/16","204.129.196.0/22",
    # Akamai (核心段)
    "23.32.0.0/13","23.64.0.0/14","23.192.0.0/11","23.197.0.0/16",
    "95.100.0.0/15","104.64.0.0/10","184.24.0.0/13","184.84.0.0/14",
    # Cloudflare Spectrum / 托管入口
    "104.16.0.0/12",
)]

# 已知云/机房 ASN (离线兜底用; 在线 ip-api hosting=true 为主判据)
DATACENTER_ASNS = {
    13335,  # Cloudflare
    16509, 14618,  # AWS
    15169, 396982,  # Google
    8075, 8068,  # Microsoft
    24940,  # Hetzner
    16276,  # OVH
    14061,  # DigitalOcean
    31898, 63949,  # Oracle
    45102,  # Alibaba
    132203,  # Tencent
    20473,  # Choopa/Vultr 早期
    60068,  # Datacamp (CDN77)
    55081,  # Hostinger
    197540,  # Hostinger EU
    51167,  # Contabo
    8560,  # 1&1 / IONOS
    42708,  # IONOS
    201814, 49981,  # Hosthatch/Hostkey 类
    212238, 46652,  # Serverius/OVH 类
    141995, 200019, 136907, 39351, 9009,  # M247/Hosthatch 等
    174, 3356, 1299, 2914, 6939,  # 骨干 (Cogent/Lumen/Arelion/NTT/Hurricane)
    199524, 206096, 49505,  # Selectel/WorldStream
    62240, 49304, 34665, 209242, 219337, 44477,
    200651, 202685, 210644, 205628, 51852, 204544, 397373, 140224,  # 小型 IDC
    54866,  # Parsebian/HydraTransit 类
    45899,  # VNPT 云? 标记为 IDC
    # ★ 实测漏网: 收购家宽段/伪装 DSL rDNS 的云边网络 (ip-api proxy=true 案例补充)
    62610,  # Zenlayer (AS62610, rDNS 带 dsl.speakeasy.net 但 proxy=true)
    60205,  # 62610 关联段
    8342,  # Deltacomputers/Evrasia 类
    9009, 47692, 62041, 56630, 57502,  # Serverius/ProXmedia/Clouvider 类
}

# 民用宽带 ASN 白名单 (离线兜底; 关键国家主流运营商)
RESIDENTIAL_ASNS = {
    # 台湾
    3462,    # Chunghwa Telecom (中华电信)
    9924, 17709, 4780, 18049,  # 亚太电信/远传/台湾大哥大/凯擘
    9269, 3491,  # 台湾硕网/和宇宽频
    # 香港
    4760, 476, 4515, 9229, 9266, 10103,  # PCCW/HKT/CUHK/HGC/HKBN/HKTBB
    9059, 38861,  # Hong Kong Broadband
    # 日本
    4713, 2516, 17676, 4721, 2497, 9605, 17511, 9318, 2518, 20193,
    # Softbank/NTT Communications/KDDI/IIJ/Sony/Plala/@nifty/JCN
    4766, 3786, 17816, 9357,
    # 韩国
    4713, 9318, 17816, 9357, 4766,  # KT/LG/SK  
    # 美国
    701, 7018, 7922, 20115, 22773, 10796, 20057, 11427, 10507, 6128,
    33363, 21928, 10777, 33660, 33661, 33662, 36466, 53417, 55136,
    20057, 19024, 12271, 11404, 6983, 33554, 7155, 30162, 10790,
    # Comcast (7922/33487/22263...) / Charter (20115/10796/20057) / Cox / AT&T / Verizon
    702, 703, 704, 705, 706, 709, 710, 711, 712, 713, 714, 715,  # legacy Verizon
    2828, 20001, 3549,  # CenturyLink/Level3 (部分为家宽)
    6167, 6162, 7018,  # AT&T
    5056,  # Cox East
    10796,  # Charter
    11351,  # TWC
    6128,  # Atlantis
    # 英国
    2856, 5607, 20650, 13285, 12576, 12725, 19541, 33950, 5413,
    # BT/TalkTalk/Orange/Virgin/Plusnet/Sky/Eclipse
    # 德国
    3320, 3209, 6805, 8888, 9145, 13237, 15366, 20879, 16097, 15594,
    # DT/Vodafone/EWE/netcup/Telefónica
    # 法国
    3215, 12322, 15557, 5410, 21590, 22869, 8228, 8220, 12670,
    # Orange/Free/SFR/Bouygues/LDN/9.tel
    # 荷兰 / 比利时
    33915, 20857, 5418, 6777, 15535, 6830, 8683,
    # KPN/Ziggo/Tele2/Solcon/Proximus/Telenet
    # 加拿大
    577, 6539, 812, 7992, 22995, 23498, 30645, 11260, 5645, 13331,
    # Bell/Rogers/Corus/Cogeco/Videotron/Telus
    # 澳大利亚 / 新西兰
    1221, 4764, 4761, 4747, 4802, 4804, 38293, 9443, 23871, 4771,
    # Telstra/Optus/iinet/AAPT/Exetel/SparkNZ
    # 新加坡 / 马来西亚
    9506, 9224, 10091, 4657, 32308, 55553, 177545, 9534, 17971, 24210,
    # Singtel/StarHub/M1/MyRepublic/TM/Maxis/Time
    # 巴西 / 拉美
    28573, 26599, 28598, 22085, 27699, 11014, 16832, 16397, 26615,
    # Claro/Vivo/Algar/Brisanet
    # 土耳其 / 俄罗斯 / 哈萨克
    9121, 34984, 15924, 31103, 47853, 25513, 12714, 8359, 12389,
    # Türk Telekom/Vodafone TR/MTS/Rostelecom/Kazakhtelecom
    # 意大利 / 西班牙
    3269, 30722, 12874, 12392, 12474, 3352, 12479, 12430,
    # Telecom Italia/Fastweb/Vodafone IT/Telefónica ES
    # 印度 / 越南 / 泰国 / 菲律宾 / 印尼
    55836, 9829, 9498, 17813, 45899, 7552, 9675, 7568, 45773, 45543,
    7590, 17457, 7552, 131293, 9336, 23969, 17816, 24099, 38251,
    # 印尼 Telkomsel/Indosat/Smartfren; 越南 Viettel/FPT; 泰国 AIS/True
}

# rDNS / ISP 名称关键词 (大小写不敏感; 离线兜底)
IDC_NAME_PATTERNS = [
    "hosting", "hoster", "datacenter", "data center", "cloud", "server",
    "vps", "dedicated", "colo", "colocation", "compute", "storage",
    "amazon", "aws", "google cloud", "microsoft", "azure", "oracle",
    "digitalocean", "linode", "vultr", "choopa", "hetzner", "ovh",
    "contabo", "m247", "leaseweb", "online s.a.s", "scaleway",
    "alibaba", "tencent", "huawei cloud", "ucloud", "jdcloud", "ksyun",
    "fastly", "cloudflare", "akamai", "cdn", "anycast", "edge network",
    "hostkey", "selectel", "aeza", "justhost", "idnica", "hostinger",
    "ionos", "1&1", "godaddy", "namecheap", "sucuri", "ispxk",
    "zenlayer", "zencom", "g-core", "gcore", "netcup", "hetzner",
]

RESIDENTIAL_NAME_PATTERNS = [
    # 通用家宽特征
    "broadband", "pppoe", "pppoa", "dsl", "cable", "fiber", "ftth",
    "fibre", "dynamic", "dial", "dialup", "residential", "home",
    "consumer", "cust", "customer", "subscriber", "pool", "dynamic-ip",
    # 台湾
    "chunghwa", "hinet", "taiwanmobile", "twn", "aptg", "kbro",
    "tfn", "sparq", "seednet", "data communication business group",
    # 香港
    "hkbn", "hong kong broadband", "pccw", "hkt", "hgc", "smartone",
    "netvigator", "citic telecom", "i-cable", "hk cable",
    # 日本
    "softbank", "ocn", "plala", "so-net", "iiJmio home", "eonet",
    "kddi", "jcom", "au broadband", "biglobe", "nifty",
    # 韩国
    "korea telecom", "kt corp", "sk broadband", "lgu+", "lg uplus",
    # 美国
    "comcast", "charter communications", "spectrum", "cox communications",
    "at&t", "at and t", "bellsouth", "sbc internet", "qwest", "centurylink",
    "verizon fios", "verizon online", "frontier communications", "windstream",
    "altice", "optimum online", "rcn", "wave broadband", "consolidated",
    "hughes", "viasat", "starlink", "mediaserv",
    # 欧洲
    "deutsche telekom", "telekom deutschland", "vodafone d2", "kabel deutschland",
    "british telecom", "bt broadband", "virgin media", "sky uk", "talktalk",
    "orange sa", "free SAS".lower(), "sfr", "bouygues", "bbox", "numericable",
    "kpn", "ziggo", "t-mobile netherlands", "proximus", "telenet",
    "telefonica", "movistar", "vodafone espana", "jazztel", "orange es",
    "telecom italia", "fastweb home", "iliad italia", "windtre",
    "swisscom", "a1 telekom", "magyar telekom", "o2 czech",
    "telia sweden", "telenor", "tele2 sweden", "bredband2",
    "rostelecom home", "mgts", "ertelecom", "dom.ru", "mtu-moscow",
    # 亚太其他
    "singtel", "starhub", "m1 limited", "myrepublic", "viewqwest",
    "maxis", "unifi", "time dotcom", "tm net", "celcom",
    "ais", "true internet", "3bb", "dtac tri", "ntc net",
    "viettel", "vnpt", "fpt telecom", "cmc telecom", "vinaphone",
    "pldt", "globe telecom", "converge ict", "sky broadband ph",
    "telkomsel", "indosat", "xl axiata", "biznet networks", "first media",
    # 拉美 / 土耳其 / 其他
    "claro", "vivo", "tim brasil", "oi internet", "net servicos",
    "turk telekom", "superonline", "ttk", "kablonet", "vodafone net",
    " kazakhtelecom", "beeline kz", "izatelecom",
    "bigpond", "iinet", "optus", "tpg internet", "aussie broadband",
    "spark nz", "vodafone nz", "2degrees", "orcon", "slingshot",
]

# 协议 → 全称 (命名用)
PROTOCOL_LABELS = {
    "vless": "VLESS", "vmess": "VMESS", "trojan": "Trojan",
    "ss": "Shadowsocks", "hysteria2": "Hysteria2", "tuic": "TUIC",
    "anytls": "AnyTLS",
}

COUNTRY_NAMES = {
    "HK": "中国香港 (Hong Kong)", "TW": "中国台湾 (Taiwan)", "JP": "日本 (Japan)",
    "SG": "新加坡 (Singapore)", "US": "美国 (United States)", "KR": "韩国 (South Korea)",
    "DE": "德国 (Germany)", "GB": "英国 (United Kingdom)", "CA": "加拿大 (Canada)",
    "FR": "法国 (France)", "NL": "荷兰 (Netherlands)", "RU": "俄罗斯 (Russia)",
    "IN": "印度 (India)", "AU": "澳大利亚 (Australia)", "IT": "意大利 (Italy)",
    "ES": "西班牙 (Spain)", "TR": "土耳其 (Turkey)", "AE": "阿联酋 (UAE)",
    "BR": "巴西 (Brazil)", "MY": "马来西亚 (Malaysia)", "TH": "泰国 (Thailand)",
    "VN": "越南 (Vietnam)", "PH": "菲律宾 (Philippines)", "ID": "印尼 (Indonesia)",
    "MX": "墨西哥 (Mexico)", "AR": "阿根廷 (Argentina)", "CL": "智利 (Chile)",
    "CO": "哥伦比亚 (Colombia)", "PE": "秘鲁 (Peru)", "ZA": "南非 (South Africa)",
    "EG": "埃及 (Egypt)", "KE": "肯尼亚 (Kenya)", "NG": "尼日利亚 (Nigeria)",
    "UA": "乌克兰 (Ukraine)", "PL": "波兰 (Poland)", "SE": "瑞典 (Sweden)",
    "NO": "挪威 (Norway)", "FI": "芬兰 (Finland)", "DK": "丹麦 (Denmark)",
    "CH": "瑞士 (Switzerland)", "AT": "奥地利 (Austria)", "BE": "比利时 (Belgium)",
    "IE": "爱尔兰 (Ireland)", "PT": "葡萄牙 (Portugal)", "GR": "希腊 (Greece)",
    "CZ": "捷克 (Czech)", "RO": "罗马尼亚 (Romania)", "HU": "匈牙利 (Hungary)",
    "IL": "以色列 (Israel)", "SA": "沙特 (Saudi Arabia)", "QA": "卡塔尔 (Qatar)",
    "KZ": "哈萨克斯坦 (Kazakhstan)", "UZ": "乌兹别克斯坦 (Uzbekistan)",
    "PK": "巴基斯坦 (Pakistan)", "BD": "孟加拉 (Bangladesh)", "LK": "斯里兰卡 (Sri Lanka)",
    "NP": "尼泊尔 (Nepal)", "MM": "缅甸 (Myanmar)", "KH": "柬埔寨 (Cambodia)",
    "LA": "老挝 (Laos)", "NZ": "新西兰 (New Zealand)", "EE": "爱沙尼亚 (Estonia)",
    "LV": "拉脱维亚 (Latvia)", "LT": "立陶宛 (Lithuania)", "BG": "保加利亚 (Bulgaria)",
    "RS": "塞尔维亚 (Serbia)", "HR": "克罗地亚 (Croatia)", "SK": "斯洛伐克 (Slovakia)",
    "SI": "斯洛文尼亚 (Slovenia)", "IS": "冰岛 (Iceland)", "LU": "卢森堡 (Luxembourg)",
    "MT": "马耳他 (Malta)", "CY": "塞浦路斯 (Cyprus)", "GE": "格鲁吉亚 (Georgia)",
    "AM": "亚美尼亚 (Armenia)", "AZ": "阿塞拜疆 (Azerbaijan)", "MD": "摩尔多瓦 (Moldova)",
    "BY": "白俄罗斯 (Belarus)", "SC": "塞舌尔 (Seychelles)", "OTHER": "其他地区 (Other)",
}


# ══════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════

def get_country_flag(country_code: str) -> str:
    if not country_code:
        return "🌐"
    cc = country_code.upper()
    if cc in ("OTHER", "ZZ", "XX", "T1", "A1", "A2"):
        return "🌐"
    if len(cc) == 2 and cc.isalpha() and cc.isascii():
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    return "🌐"


def b64_decode(data: str) -> str:
    """容错 base64 解码 (支持 URL-safe / 缺失 padding)"""
    data = data.strip()
    try:
        pad = -len(data) % 4
        if data and data[-1] not in "=":
            data += "=" * pad
        raw = base64.urlsafe_b64decode(data)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        pass
    try:
        raw = base64.b64decode(data + "=" * (-len(data) % 4))
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════════
# HTTP 会话 (两分离设计):
#
# 【设计定位: 测活视角 = GitHub Actions 美国微软云 (海外直连节点)】
#   节点从海外可达即入库; 大陆用户经前置代理(链式)访问 —— 与 CI 同视角。
#   因此: 本地开发机 (大陆网络) 只用于调试, 抓订阅源需借系统代理过墙;
#   生产环境 (Actions) 无代理直连, 天然正确。
#
#   - DIRECT_SESSION (trust_env=True): 抓订阅源/下载数据库/IP情报/Scamalytics。
#       本地: 经系统代理 (v2rayN) 过墙; Actions: 直连 — 两种环境都正确。
#   - PROBE_SESSION (trust_env=False): 经 sing-box SOCKS 探测节点。
#       强制隔离环境代理, 保证测的是"运行机→节点"真实链路。
#       (本地调试时受 GFW 影响的失败 ≠ 节点死亡, Actions 上会得到真实结果;
#        宁可本地多杀, 不可 CI 误杀 — 生产判定以 Actions 为准)
# ══════════════════════════════════════════════════════════════════

DIRECT_SESSION = requests.Session()
DIRECT_SESSION.trust_env = True    # 跟随系统/环境代理 (本地大陆网络抓 GitHub 需要; Actions 无代理直连不受影响)
DIRECT_SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})

PROBE_SESSION = requests.Session()
PROBE_SESSION.trust_env = False    # 强制隔离: 节点探测链路绝不经本机代理, 防污染测试结果
PROBE_SESSION.headers.update({"User-Agent": USER_AGENT})


def http_get(url: str, timeout: int = 15, headers: dict = None) -> requests.Response:
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        h.update(headers)
    return DIRECT_SESSION.get(url, timeout=timeout, headers=h)


def ensure_directories():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
    os.makedirs(RUNTIME_DIR, exist_ok=True)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip())
        return True
    except ValueError:
        return False


def parse_host_port(hostinfo: str):
    """解析 '[v6]:port' 或 'v4:port' 或 'host:port'"""
    hostinfo = hostinfo.strip()
    if hostinfo.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostinfo)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else 0
        return hostinfo, 0
    if hostinfo.count(":") == 1:
        host, _, port = hostinfo.rpartition(":")
        if host and port.isdigit():
            return host, int(port)
    if hostinfo.count(":") > 1 and is_ip_literal(hostinfo):
        return hostinfo, 0  # 裸 IPv6 无端口
    parts = hostinfo.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return hostinfo, 0


# ══════════════════════════════════════════════════════════════════
# 环境准备 (sing-box / GeoLite)
# ══════════════════════════════════════════════════════════════════

def download_file(url: str, dest: str, timeout: int = 300, retries: int = 3):
    """下载文件到本地; 分块流式 + 原子替换 + 重试 + 镜像切换
    (GitHub 直连失败自动尝试 jsdelivr 镜像 — 本地大陆网络/CI 偶发限流都更稳)"""
    if os.path.exists(dest) and os.path.getsize(dest) > 1024:
        return
    # 镜像: github.com/OWNER/REPO/... → cdn.jsdelivr.net/gh/OWNER/REPO@...
    mirrors = [url]
    m = re.match(r"^https://(?:github\.com|raw\.githubusercontent\.com)/([^/]+)/([^/]+)/(?:raw|releases/download)/(.+)$", url)
    if m and "releases/download" not in url:
        owner, repo, path = m.groups()
        mirrors.append(f"https://cdn.jsdelivr.net/gh/{owner}/{repo.replace('.git','')}@{path}")
    print(f"[*] 下载: {url}")
    tmp = dest + ".part"
    last_err = None
    for mirror in mirrors:
        for attempt in range(retries):
            try:
                with DIRECT_SESSION.get(mirror, timeout=timeout, stream=True,
                                        headers={"Accept": "*/*"}) as r:
                    r.raise_for_status()
                    with open(tmp, "wb") as f:
                        for chunk in r.iter_content(chunk_size=1 << 20):
                            if chunk:
                                f.write(chunk)
                if os.path.getsize(tmp) < 1024:
                    raise RuntimeError(f"下载不完整: {os.path.getsize(tmp)} bytes")
                os.replace(tmp, dest)
                return
            except Exception as e:
                last_err = e
                if attempt < retries - 1:
                    wait = 3 * (attempt + 1)
                    print(f"[!] 下载失败 (第{attempt+1}次): {str(e)[:70]} — {wait}s 后重试")
                    time.sleep(wait)
        if len(mirrors) > 1 and mirror != mirrors[-1]:
            print(f"[!] 切换镜像: {mirrors[1]}")
    # 清理失败的半截文件
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except OSError:
        pass
    raise RuntimeError(f"下载最终失败 ({mirrors[0]}): {last_err}")


def setup_environment():
    print("[*] 准备 sing-box 内核与 GeoLite2 离线数据库 ...")
    os.makedirs(RUNTIME_DIR, exist_ok=True)

    # --- sing-box ---
    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")
    if not os.path.exists(exe) or os.path.getsize(exe) < 1024:
        system = "windows" if os.name == "nt" else "linux"
        ext = "zip" if system == "windows" else "tar.gz"
        url = (f"https://github.com/SagerNet/sing-box/releases/download/"
               f"{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION.lstrip('v')}-{system}-amd64.{ext}")
        archive = os.path.join(RUNTIME_DIR, f"sing-box.{ext}")
        download_file(url, archive)
        if system == "windows":
            with zipfile.ZipFile(archive) as z:
                for name in z.namelist():
                    if name.endswith("sing-box.exe"):
                        with z.open(name) as src, open(exe, "wb") as dst:
                            shutil.copyfileobj(src, dst)
        else:
            with tarfile.open(archive) as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        f = t.extractfile(m)
                        with open(exe, "wb") as dst:
                            shutil.copyfileobj(f, dst)
        os.chmod(exe, 0o755)
        try:
            os.remove(archive)
        except OSError:
            pass
    # 校验内核可运行
    try:
        ver = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=20)
        first = (ver.stdout or "").splitlines()[0] if ver.stdout else "?"
        print(f"[+] sing-box 内核就绪: {first.strip()}")
    except Exception as e:
        print(f"[!] sing-box 内核无法运行: {e}")
        raise

    # --- GeoLite2 数据库 ---
    country_db = os.path.join(RUNTIME_DIR, "Country.mmdb")
    asn_db = os.path.join(RUNTIME_DIR, "ASN.mmdb")
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb", country_db)
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb", asn_db)
    print(f"[+] GeoLite 数据库就绪: Country={os.path.getsize(country_db)//1024}KB, ASN={os.path.getsize(asn_db)//1024}KB")


# ═══════════════════════════════════════════N═══════════════════════
# 节点 URI 解析 (全协议 → sing-box outbound JSON)
# ═══════════════════════════════════════════N═══════════════════════

def _query_dict(query: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}


def _parse_tls_params(params: dict, host: str) -> dict:
    """从 URI query 提取 TLS/Reality 设置 → sing-box 格式"""
    security = params.get("security", "").lower()
    tls = {}
    if security == "reality":
        pbk = params.get("pbk", "")
        if not pbk:
            return None
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "utls": {"enabled": True, "fingerprint": params.get("fp", "chrome")},
            "reality": {"enabled": True, "public_key": pbk, "short_id": params.get("sid", "")},
        }
    elif security in ("tls", "xtls"):
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
            "alpn": params.get("alpn", "").split(",") if params.get("alpn") else None,
        }
        if params.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": params["fp"]}
        if tls.get("alpn") is None:
            del tls["alpn"]
    return tls or None


def _parse_transport(params: dict) -> dict:
    """从 URI query 提取传输层 → sing-box transport 格式"""
    network = params.get("type", "tcp").lower()
    if network in ("tcp", "none", "raw"):
        return None
    if network == "ws":
        t = {"type": "ws"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["headers"] = {"Host": params["host"]}
        # 0-RTT early data (v2ray ws 0-RTT: path 含 ?ed=2560 时由 max-early-data 指定)
        if params.get("ed"):
            t["max_early_data"] = 2560
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if network in ("grpc", "gun"):
        t = {"type": "grpc"}
        if params.get("serviceName"):
            t["service_name"] = urllib.parse.unquote(params["serviceName"])
        return t
    if network in ("h2", "http"):   # v2ray 生态两种写法都有: type=h2 / type=http (导出用 http, 兼容两者)
        t = {"type": "http"}
        host = params.get("host", "")
        if host:
            t["host"] = [h for h in host.split(",") if h]
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        return t
    if network == "httpupgrade":
        t = {"type": "httpupgrade"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["host"] = params["host"]
        return t
    return None


def parse_vless(uri: str):
    """vless://uuid@host:port?params#name"""
    m = re.match(r"^vless://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    user, host, port, query, _name = m.groups()
    params = _query_dict(query or "")
    tls = _parse_tls_params(params, host)
    if params.get("security", "").lower() == "reality" and tls is None:
        return None  # reality 缺 pbk 无法测
    outbound = {
        "type": "vless",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": user,
    }
    flow = params.get("flow", "")
    if flow and ("vision" in flow or "xtls" in flow):
        outbound["flow"] = flow
    if tls:
        outbound["tls"] = tls
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_vmess(uri: str):
    """vmess://base64({v,ps,add,port,id,aid,net,tls,sni,path,host,type})"""
    data = json.loads(b64_decode(uri[8:]))
    if not data:
        return None
    server = str(data.get("add", "")).strip()
    port = int(data.get("port", 0) or 0)
    if not server or port <= 0:
        return None
    outbound = {
        "type": "vmess",
        "tag": "node",
        "server": server,
        "server_port": port,
        "uuid": str(data.get("id", "")).strip(),
        "security": "auto",
    }
    aid = int(data.get("aid", 0) or 0)
    if aid > 0:
        outbound["alter_id"] = aid
    net = str(data.get("net", "tcp")).lower()
    if data.get("tls") in ("tls", "1", 1, True):
        outbound["tls"] = {
            "enabled": True,
            "server_name": str(data.get("sni") or data.get("host") or server).strip(),
            "insecure": str(data.get("verify_cert", "false")).lower() in ("true", "1"),
        }
    transport = None
    if net in ("ws",):
        transport = {"type": "ws"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["headers"] = {"Host": str(data["host"])}
    elif net in ("grpc", "gun"):
        transport = {"type": "grpc"}
        if data.get("path"):
            transport["service_name"] = str(data["path"])
    elif net == "h2":
        transport = {"type": "http"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = [str(data["host"])]
    elif net == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = str(data["host"])
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_trojan(uri: str):
    """trojan://password@host:port?params#name"""
    m = re.match(r"^trojan://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    password, host, port, query, _ = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "trojan",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("fp"):
        outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"]}
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_ss(uri: str):
    """ss://base64(method:password)@host:port#name  或  ss://method:password@... (SIP002)"""
    body = uri[5:].split("#", 1)[0]
    name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    # SIP002: method:password@host:port
    if "@" in body:
        userinfo, _, hostinfo = body.rpartition("@")
        host, port = parse_host_port(hostinfo.split("/")[0].split("?")[0])
        method, password = "", ""
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
        else:
            dec = b64_decode(userinfo)
            if ":" in dec:
                method, _, password = dec.partition(":")
        method = urllib.parse.unquote(method)
        password = urllib.parse.unquote(password)
        if not (host and port > 0 and method and password):
            return None
        return _ss_outbound(host, port, method, password)
    # legacy: base64(method:password@host:port)
    dec = b64_decode(body)
    if "@" in dec:
        userinfo, _, hostinfo = dec.rpartition("@")
        host, port = parse_host_port(hostinfo.strip())
        method, _, password = userinfo.partition(":")
        if host and port > 0 and method:
            return _ss_outbound(host, port, urllib.parse.unquote(method), urllib.parse.unquote(password))
    return None


def _ss_outbound(host, port, method, password):
    return {
        "type": "shadowsocks",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "method": method.strip().lower(),
        "password": password,
    }


def parse_hysteria2(uri: str):
    """hy2:// / hysteria2:// auth@host:port?sni=..&obfs=salamander&obfs-password=..&insecure=1
    注: auth 可能含 : / 等特殊字符 (如 https:// 前缀的密码) — 以最后一个 @ 为锚点分割"""
    prefix = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
    body = uri[len(prefix):].split("#", 1)[0]
    # 以最后一个 @ 分割 (密码内可能含 @); host 部分不含 @
    at = body.rfind("@")
    if at <= 0:
        return None
    auth, rest = body[:at], body[at+1:]
    m = re.match(r"^(\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?]([^#]*))?$", rest)
    if not m:
        return None
    host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "hysteria2",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(auth),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true") or params.get("insecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("obfs", "") and params["obfs"] not in ("none", ""):
        outbound["obfs"] = {"type": params["obfs"], "password": params.get("obfs-password", "")}
    mport = params.get("mport") or params.get("ports")
    if mport:
        # 实测验证: server_ports 只接受 "start:end" 区间; 裸单端口 "443" 会 FATAL
        # 单端口保留在 server_port, 区间放 server_ports (两者可共存, 实测 check 通过)
        singles, ranges = [], []
        for part in str(mport).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, _, b = part.partition("-")
                if a.strip().isdigit() and b.strip().isdigit():
                    if a.strip() == b.strip():
                        singles.append(a.strip())
                    else:
                        ranges.append(f"{a.strip()}:{b.strip()}")
            elif part.isdigit():
                singles.append(part)
        if ranges or singles:
            # 全部转为 "start:end" 区间格式 (实测: 裸单端口 FATAL)
            outbound["server_ports"] = ranges + [f"{s}:{s}" for s in singles]
            outbound.pop("server_port", None)  # 端口跳跃节点无固定单端口
    return outbound


def _parse_port_range(spec: str):
    """'2087-2097,443' → sing-box server_ports 格式 ['2087:2097', '443:443'] (实测: 裸单端口 FATAL, 必须区间)"""
    result = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                result.append(f"{a.strip()}:{b.strip()}")
        elif part.isdigit():
            result.append(f"{part}:{part}")
    return result


def parse_tuic(uri: str):
    """tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni=..&udp_relay_mode=native#name"""
    m = re.match(r"^tuic://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port, query = m.groups()
    if ":" not in userinfo:
        return None
    uuid_, _, password = userinfo.partition(":")
    params = _query_dict(query or "")
    outbound = {
        "type": "tuic",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": urllib.parse.unquote(uuid_),
        "password": urllib.parse.unquote(password),
        "congestion_control": params.get("congestion_control", "bbr"),
        "udp_relay_mode": params.get("udp_relay_mode", "native"),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("allow_insecure", "0") in ("1", "true"),
            "alpn": [a for a in params.get("alpn", "h3").split(",") if a],
        },
    }
    return outbound


def parse_anytls(uri: str):
    """anytls://password@host:port?sni=..&insecure=1#name"""
    m = re.match(r"^anytls://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    password, host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "anytls",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("insecure", "0") in ("1", "true") or params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    return outbound


def parse_ssh(uri: str):
    """ssh://user:pass@host:port#name (少见于免费池, 顺手支持)"""
    m = re.match(r"^ssh://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)?", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port = m.groups()
    outbound = {
        "type": "ssh",
        "tag": "node",
        "server": host,
        "server_port": int(port or 22),
        "user": urllib.parse.unquote(userinfo.split(":")[0]),
    }
    if ":" in userinfo:
        outbound["user"] = urllib.parse.unquote(userinfo.split(":")[0])
        outbound["password"] = urllib.parse.unquote(userinfo.split(":", 1)[1])
    return outbound


PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "hy2://": parse_hysteria2,
    "hysteria2://": parse_hysteria2,
    "tuic://": parse_tuic,
    "anytls://": parse_anytls,
    "ssh://": parse_ssh,
}

# 排除明显加密残缺/占位节点
BLACKLIST_NAME_HINTS = re.compile(r"(剩余流量|流量重置|expire|expired|官网|套餐|telegram\.me|t\.me/|获取订阅)", re.I)


def parse_node_uri(uri: str):
    """解析节点 URI → (outbound, server, port, protocol) ; 失败返回 None"""
    for prefix, parser in PARSERS.items():
        if uri.startswith(prefix):
            try:
                out = parser(uri)
            except Exception:
                return None
            if not out:
                return None
            proto = out["type"]
            port = out.get("server_port")
            if port is None:  # 端口跳跃节点: 无固定端口, 取区间首个起点用于预检
                ports = out.get("server_ports") or []
                first = ports[0].split(":")[0] if ports else "0"
                port = int(first)
            if port <= 0:
                return None
            return out, out["server"], int(port), proto
    return None


def extract_nodes_from_text(text: str) -> set:
    results = set()
    if not text:
        return results
    probe = text.strip()
    # 最多三层 base64 解包 (订阅常见整体 base64)
    for _ in range(3):
        if any(p in probe for p in ("vmess://", "vless://", "ss://", "trojan://",
                                     "hy2://", "hysteria2://", "tuic://", "anytls://")):
            break
        decoded = b64_decode(probe)
        if not decoded or decoded == probe:
            break
        probe = decoded
    # 直接文本也可能混杂 base64 行
    lines_blob = probe
    pattern = (r'((?:vmess|vless|trojan|ss|hy2|hysteria2|tuic|anytls|ssh)://'
               r'[^\s"\'<>\\]+)')
    for m in re.findall(pattern, lines_blob):
        clean = m.strip().rstrip(".,;'\"")
        if len(clean) > 12:
            results.add(clean)
    return results


def fetch_raw_nodes() -> list:
    nodes = set()
    print("[*] 抓取全部订阅源 ...")

    def _fetch(url):
        last_err = None
        # 重试 2 次 (网络抖动/GFW 间歇性重置; 退避 3s)
        for attempt in range(3):
            try:
                r = http_get(url, timeout=30)
                if r.status_code == 200:
                    got = extract_nodes_from_text(r.text)
                    return url, got, None
                last_err = f"HTTP {r.status_code}"
            except Exception as e:
                last_err = str(e)[:70]
            if attempt < 2:
                time.sleep(3)
        return url, set(), last_err

    with ThreadPoolExecutor(MAX_WORKERS_FETCH) as ex:
        futs = [ex.submit(_fetch, u) for u in SOURCE_URLS]
        for f in as_completed(futs):
            url, got, err = f.result()
            if err:
                print(f"[!] 拉取失败 {url} → {err}")
            else:
                print(f"[+] {url} → {len(got)} 节点")
            nodes.update(got)
    print(f"[*] 初始抓取总量: {len(nodes)}")
    return list(nodes)


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 A: 端口预检 (削减死节点, 避免后面浪费 sing-box 全流程)
# ═══════════════════════════════════════════N═══════════════════════

# DoH 域名解析 (Cloudflare): 防 DNS 污染 (本地大陆网络); Actions 上顺带跳过其国内 DNS 限制
_DNS_CACHE = {}

def resolve_host(host: str) -> str:
    """DoH 解析 (带本地缓存); 失败退回系统 DNS"""
    if not host or is_ip_literal(host):
        return host or ""
    if host in _DNS_CACHE:
        return _DNS_CACHE[host]
    # 1) DoH (Cloudflare 1.1.1.1, 走 DIRECT_SESSION 可过墙)
    try:
        r = DIRECT_SESSION.get(
            f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=A",
            headers={"Accept": "application/dns-json"}, timeout=5)
        if r.status_code == 200:
            answers = r.json().get("Answer") or []
            for a in answers:
                if a.get("type") == 1 and a.get("data"):
                    _DNS_CACHE[host] = a["data"]
                    return a["data"]
    except Exception:
        pass
    # 2) 系统 DNS 兜底
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        return ""


def knock_port(server: str, port: int, protocol_type: str) -> bool:
    """TCP 直连预检 (DoH 解析防本地 DNS 污染); QUIC 类直接放行阶段B
    注: 预检失败不淘汰 (本地大陆视角的假死 ≠ 节点死亡), 只影响排序;
        生死由阶段B sing-box 全流程测活裁决 (Actions 海外视角)"""
    if protocol_type in ("hysteria2", "tuic"):
        # QUIC 无法轻量预检 UDP 端口连通性, 且本地 UDP 常被 QoS → 放行交阶段B
        return True
    try:
        ip = resolve_host(server)
        if not ip:
            return False
        with socket.create_connection((ip, port), timeout=PORT_KNOCK_TIMEOUT):
            return True
    except Exception:
        return False


def prefilter_candidates(candidates: list) -> list:
    """端口预检: 通过者优先, 未通过者降级保留 (防止本地网络/GFW 视角误杀;
    真正生死由阶段B sing-box 全流程测活裁决 — Actions 海外视角)"""
    print(f"[*] 端口预检 (TCP {PORT_KNOCK_TIMEOUT}s): {len(candidates)} 候选 ...")
    passed, deferred = [], []

    def _knock(item):
        raw, outbound, server, port, proto = item
        return knock_port(server, port, proto)

    with ThreadPoolExecutor(max_workers=64) as ex:
        # ex.map 保序返回; 通过者优先, 未通过降级保留 (不淘汰, 防本地视角误杀)
        for item, ok in zip(candidates, ex.map(_knock, candidates)):
            (passed if ok else deferred).append(item)
    print(f"[+] 预检通过: {len(passed)} | 预检未过(保留低优先级待全测): {len(deferred)}")
    # 预检未过的仍进入全流程 (只是排在后面) — 交给 sing-box 真实裁决
    return passed + deferred


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B: sing-box 真实测活
# ═══════════════════════════════════════════N═══════════════════════

def _alloc_socks_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_test_config(outbound: dict, socks_port: int, chain_relay: dict = None) -> dict:
    node = dict(outbound)
    node["tag"] = "node"

    outbounds = [node, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]

    # ══ 链式前置 (家宽链式复测用) ═════════════════════════════════════
    # chain_relay: 已验证存活的 sing-box outbound dict — node 经它转发 (detour 双跳)
    # 模拟用户 v2rayN "链式/前置代理" 场景: 前置 → 家宽节点 → 目标
    if chain_relay:
        relay = dict(chain_relay)
        relay["tag"] = "chain-relay"
        # relay 自身剥 detour (避免与 node 的 detour 循环)
        relay.pop("detour", None)
        outbounds.append(relay)
        node["detour"] = "chain-relay"

    # ══ 前置代理 (链式) ═════════════════════════════════════════════
    # 模拟 GitHub Actions 海外视角:
    #   - 本地大陆开发机: 经前置代理(默认 v2rayN 127.0.0.1:10808)出海 → 等效 CI 视角
    #     (大陆直连目标节点会被 GFW 拦截, 造成本地假死 ≠ 节点死亡)
    #   - GitHub Actions: FRONT_PROXY 为空 → 直连 (Azure US 本就是海外视角)
    # 用法: 环境变量 FRONT_PROXY=socks5://127.0.0.1:10808
    front = os.environ.get("FRONT_PROXY", "").strip()
    if front and not chain_relay:
        # 解析 socks5://host:port → socks outbound
        m = re.match(r"^(socks5h?|http)://([^:]+):(\d+)$", front)
        if m:
            scheme, fhost, fport = m.groups()
            ftype = "socks" if scheme.startswith("socks5") else "http"
            front_out = {
                "type": ftype, "tag": "front-proxy",
                "server": fhost, "server_port": int(fport),
            }
            if ftype == "socks":
                front_out["version"] = "5"
            outbounds.append(front_out)
            # 节点出站流量经前置代理 (detour 链式)
            node["detour"] = "front-proxy"
            print_once("_FRONT_ENABLED", f"[*] 前置代理已启用: {front} (模拟 CI 海外视角)")

    config = {
        "log": {"level": "warn"},   # 实测: silent 不是合法级别 (trace/debug/info/warn/error/fatal/panic)
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
            "sniff": False,
        }],
        "outbounds": outbounds,
        "route": {"rules": [], "final": "node"},
    }
    return config


_PRINTED_ONCE = set()


def print_once(key: str, msg: str):
    if key not in _PRINTED_ONCE:
        _PRINTED_ONCE.add(key)
        print(msg)


def test_single_node(item, keep_alive_check=True):
    """返回 dict 或 None; 含: 活性/延迟/出口IP/国家/ASN/ISP/速度/MITM"""
    raw, outbound, server, port, proto = item
    socks_port = _alloc_socks_port()
    task_id = uuid.uuid4().hex[:10]
    cfg_path = os.path.join(RUNTIME_DIR, f"sb_{task_id}.json")

    # ★ 链式前置 (chain relay): 注入已验证存活节点作前置 (chain_retest 用, 模拟 v2rayN 链式)
    chain_out = None
    chain_json = os.environ.get("CHAIN_RELAY_OUT", "").strip()
    if chain_json:
        try:
            chain_out = json.loads(chain_json)
        except Exception:
            chain_out = None
    config = build_test_config(outbound, socks_port, chain_relay=chain_out)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f)

    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")

    # --- 0) sing-box check 预校验: 快速淘汰 schema 错误 (实测可发现 2022 密钥长度/端口区间等错误) ---
    try:
        chk = subprocess.run([exe, "check", "-c", cfg_path],
                             capture_output=True, text=True, timeout=15,
                             creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        if chk.returncode != 0:
            return None  # 配置级错误 → 该节点无法被 sing-box 使用, 必淘汰
    except Exception:
        pass  # check 本身失败不阻止后续 run 尝试

    proc = None
    result = None
    try:
        proc = subprocess.Popen(
            [exe, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )
        # 等 SOCKS 端口就绪 (主动探测而非盲 sleep — 修复旧版误杀)
        deadline = time.time() + 6
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                break  # 进程崩溃 (配置错误/端口冲突)
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.4):
                    ready = True
                    break
            except Exception:
                time.sleep(0.15)
        if not ready:
            return None

        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
                   "https": f"socks5h://127.0.0.1:{socks_port}"}

        # --- 1) 活性探测: 分层超时重试 (首击宽 12s 容慢节点保准确率; 重试窄 4s 快速放弃死节点) ---
        alive_hits, latency_ms = 0, 99999
        t0 = time.time()
        for i, url in enumerate(LIVENESS_URLS):
            timeout = PROBE_TIMEOUT if i == 0 else PROBE_RETRY_TIMEOUT
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
                if r.status_code in (204, 200):
                    alive_hits += 1
                    latency_ms = min(latency_ms, (time.time() - t0) * 1000)
                    break  # 任一成功即可
            except Exception:
                continue
        if alive_hits == 0:
            return None

        # --- 2) 真实出口 IP (多路冗余) ---
        exit_ip, exit_country, exit_asn, exit_asn_org, exit_isp = None, None, None, None, None
        for url in IP_ECHO_URLS:
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=IP_ECHO_TIMEOUT)
                if r.status_code != 200:
                    continue
                j = r.json()
                ip = (j.get("ip") or j.get("query") or j.get("your_ip") or "").strip()
                if not ip:
                    continue
                exit_ip = ip
                if url.startswith("https://api.ip.sb"):
                    exit_country = j.get("country_code")
                    exit_asn = j.get("asn")
                    exit_asn_org = (j.get("asn_organization") or j.get("organization") or "")
                    exit_isp = (j.get("isp") or j.get("organization") or "")
                elif url.startswith("https://ipinfo.io"):
                    exit_country = exit_country or (j.get("country") or "").upper()
                    org = j.get("org") or ""
                    if org and not exit_asn:
                        mm = re.match(r"^AS(\d+)\s+(.*)", org)
                        if mm:
                            exit_asn, exit_asn_org = int(mm.group(1)), mm.group(2)
                    exit_isp = exit_isp or org
                elif "ip-api.com" in url:
                    exit_country = exit_country or (j.get("countryCode") or "").upper()
                    exit_asn = exit_asn or j.get("as")
                    exit_asn_org = exit_asn_org or j.get("asname") or j.get("org") or ""
                    exit_isp = exit_isp or j.get("isp") or j.get("org") or ""
                break
            except Exception:
                continue

        # --- 3) MITM 劫持检测 (轻量: 复用活性首击的 gstatic 请求已验证证书链) ---
        # 3a) 独立复检一次带 verify=True 的请求: SSLError = TLS 拦截
        mitm_risk = False
        try:
            r = PROBE_SESSION.get("https://www.gstatic.com/generate_204", proxies=proxies,
                                  timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code in (204, 200):
                mitm_risk = False
            else:
                mitm_risk = r.status_code in (301, 302, 403, 407, 502, 503) or len(r.content) > 0
        except requests.exceptions.SSLError:
            # 证书链验证失败 = TLS 拦截 (MITM) 或劣质自签劫持
            mitm_risk = True
        except Exception:
            pass  # 网络层失败不算 MITM (活性探测已通过)

        # 3b) cloudflare trace: warp=on = 套壳 WARP 节点 (非真实出口, 降权标记) — 4s 窄超时
        is_warp = False
        try:
            r = PROBE_SESSION.get(TRACE_URL, proxies=proxies, timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code == 200:
                if re.search(r"^warp=on", r.text, re.M):
                    is_warp = True
        except Exception:
            pass

        # --- 4) 断流检测: 限时下载测速 (chunked 读 + 空闲计时; 多端点兜底防测速站被屏蔽) ---
        # 断流签名: 连接建立且首包正常, 但中途停止送数据 → 空闲超时强断
        speed_bps = 0
        for speed_url in SPEED_TEST_URLS:
            downloaded = 0
            t_speed = time.time()
            last_chunk_time = time.time()
            try:
                with PROBE_SESSION.get(speed_url, proxies=proxies,
                                       timeout=(5, SPEED_TEST_BUDGET), stream=True) as r:
                    if r.status_code == 200:
                        for chunk in r.iter_content(chunk_size=65536):
                            now = time.time()
                            if chunk:
                                downloaded += len(chunk)
                                last_chunk_time = now
                            # 总预算超限 → 正常截断 (拿已有数据算吞吐)
                            if now - t_speed > SPEED_TEST_BUDGET:
                                break
                            # 空闲 > 3s 无任何数据 → 断流签名, 立即中止
                            if now - last_chunk_time > 3.0:
                                break
                elapsed = max(time.time() - t_speed, 0.001)
                if downloaded > 0:
                    speed_bps = int(downloaded / elapsed)
                    break  # 首个成功端点的结果即有效
            except Exception:
                continue
        # 全部端点都失败 (下载0字节) → 视为断流 (活性已过但无法承载数据流)

        # 断流判定: 连 70KB/s 都达不到 → 断流/极慢, 真实不可用
        is_stalled = speed_bps < SPEED_MIN_BYTES_PER_S

        result = {
            "raw": raw,
            "server": server,
            "port": port,
            "proto": proto,
            "alive": True,
            "latency_ms": int(latency_ms),
            "exit_ip": exit_ip,
            "exit_country_online": exit_country,
            "exit_asn_online": exit_asn,
            "exit_asn_org_online": (exit_asn_org or "")[:120],
            "exit_isp_online": (exit_isp or "")[:120],
            "mitm_risk": mitm_risk,
            "is_warp": is_warp,
            "speed_bps": speed_bps,
            "is_stalled": is_stalled,
        }
        return result
    except Exception:
        return None
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        try:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except OSError:
            pass


def run_liveness_test(candidates: list) -> list:
    print(f"[*] sing-box 全协议真实测活: {len(candidates)} 节点 (并发 {MAX_WORKERS_TEST}) ...")
    results = []
    done_count = [0]

    def _work(item):
        return test_single_node(item)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TEST) as ex:
        futs = {ex.submit(_work, it): it for it in candidates}
        for fut in as_completed(futs):
            done_count[0] += 1
            r = fut.result()
            if r:
                results.append(r)
            if done_count[0] % 40 == 0:
                print(f"[*] 测活进度: {done_count[0]}/{len(candidates)}, 通过 {len(results)}")

    alive = [r for r in results if r["alive"] and not r["is_stalled"]]
    mitm = sum(1 for r in results if r["mitm_risk"])
    stalled = sum(1 for r in results if r["is_stalled"])
    print(f"[+] 测活完成: 真活 {len(alive)} | 断流淘汰 {stalled} | MITM 风险 {mitm}")
    return results  # 保留全部信息, 分类阶段再决定去留


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B2: 家宽链式复测 (chain relay retest)
# ════════════════════════════════════════════════════════════════════

def chain_retest(test_results: list) -> list:
    """家宽链式复测: 模拟用户 v2rayN 链式 (前置 → 家宽节点 → 目标)

    实测背景: 用户反馈家宽节点在 v2rayN 链式代理下仅 ~50% 可用。
    根因: 单跳测活通过 ≠ 双跳可用 (部分节点不允许"已被代理的流量"再入,
    或 UDP/QUIC 节点无法过 socks 链)。解决: CI 里用最快存活节点当前置,
    对家宽候选做双跳复测 — 双跳通过的才进家宽专区。

    流程: 先跑一遍轻量分类拿到家宽候选 → 取最快存活节点做 relay →
    家宽候选逐个双跳复测 → 双跳也活的保留, 双跳死的降级普通区。
    返回: 更新 net_type 后的 test_results (原对象原地修改)。
    """
    # 1) 轻量分类拿家宽候选 (复用 classify_and_export 的候选判定, 但不导出)
    #    家宽候选 = ip-api/mmdb 六信号判 residential/mobile 的节点
    ip_api_info = {}
    all_exit_ips = list({r["exit_ip"] for r in test_results if r.get("exit_ip")})
    if all_exit_ips:
        try:
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
        except Exception as e:
            print(f"[!] 链式复测: ip-api 批量失败 ({e}), 跳过链式复测")
            return test_results

    res_candidates = {}
    for r in test_results:
        if not (r.get("alive") and not r.get("is_stalled")):
            continue
        rec = ip_api_info.get(r.get("exit_ip"), {})
        t, c = classify_network_type(r["exit_ip"], r.get("exit_country_online"),
                                     r.get("exit_asn_online"),
                                     r.get("exit_asn_org_online"), rec or None)
        if t in ("residential", "mobile") and c >= 60:
            res_candidates[(r["server"].lower(), r["port"], r["proto"])] = r

    if not res_candidates:
        print("[*] 链式复测: 无家宽候选, 跳过")
        return test_results
    print(f"[*] 链式复测: {len(res_candidates)} 个家宽候选")

    # 2) 选 relay: 全体存活节点里延迟最低、非家宽候选自己 (避免自己套自己)
    alive_sorted = sorted(
        [r for r in test_results if r.get("alive") and not r.get("is_stalled")],
        key=lambda x: x.get("latency_ms", 99999))
    relay_result = None
    for r in alive_sorted:
        if (r["server"].lower(), r["port"], r["proto"]) not in res_candidates:
            relay_result = r
            break
    if not relay_result:
        print("[!] 链式复测: 无可用 relay 节点, 跳过")
        return test_results
    relay_out = relay_result.get("outbound")
    if not relay_out:
        # 重新解析 relay 的 raw 拿 outbound
        p = parse_node_uri(relay_result["raw"])
        if p:
            relay_out = p[0]
    if not relay_out:
        print("[!] 链式复测: relay outbound 构建失败, 跳过")
        return test_results
    # relay 必须剥离 detour (前置链复用时防循环)
    relay_out = dict(relay_out)
    relay_out.pop("detour", None)
    print(f"[*] 链式 relay: {relay_result['proto']} {relay_result['server']}:{relay_result['port']} "
          f"(延迟 {relay_result['latency_ms']}ms)")

    # 3) 家宽候选逐个双跳复测 (注入 CHAIN_RELAY_OUT, test_single_node 自动加 detour)
    os.environ["CHAIN_RELAY_OUT"] = json.dumps(relay_out)
    chain_alive, chain_dead = [], []
    try:
        for key, r in res_candidates.items():
            item = (r["raw"], r.get("outbound") or (parse_node_uri(r["raw"]) or [None])[0],
                    r["server"], r["port"], r["proto"])
            if not item[1]:
                chain_dead.append(r)
                continue
            recheck = test_single_node(item)
            if recheck and recheck.get("alive") and not recheck.get("is_stalled"):
                chain_alive.append(r)
            else:
                chain_dead.append(r)
    finally:
        os.environ.pop("CHAIN_RELAY_OUT", None)

    # 4) 双跳失败的 → 降级普通区 (不从订阅删除, 用户直连场景仍可能可用)
    for r in chain_dead:
        r["_chain_failed"] = True

    print(f"[+] 链式复测完成: 双跳可用 {len(chain_alive)} | 双跳失败降级 {len(chain_dead)}")
    return test_results


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 C: 出口 IP 批量情报 (ip-api.com 免费 batch) + 离线兜底
# ═══════════════════════════════════════════N═══════════════════════

def ip_api_batch_lookup(ip_list: list) -> dict:
    """ip-api.com batch (免费 HTTP, ≤100/req, 15 req/min → 1500 IP/min)"""
    info = {}
    session = requests.Session()
    session.trust_env = True  # 直连即可; ip-api.com 免费层全球可达 (CI 无代理/本地走系统代理均可)
    total_batches = (len(ip_list) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
    for bi, i in enumerate(range(0, len(ip_list), IP_API_BATCH_SIZE), 1):
        chunk = ip_list[i:i + IP_API_BATCH_SIZE]
        payload = [{"query": ip} for ip in chunk]
        for attempt in range(3):
            try:
                r = session.post(IP_API_BATCH_URL, json=payload, timeout=20)
                if r.status_code == 200:
                    for rec in r.json():
                        q = rec.get("query")
                        if q:
                            info[q] = rec
                    break
                elif r.status_code == 429:
                    time.sleep(4 + attempt * 3)
                else:
                    time.sleep(2)
            except Exception:
                time.sleep(2)
        if total_batches >= 3 and (bi % 5 == 0 or bi == total_batches):
            print(f"[*] ip-api 进度: 批 {bi}/{total_batches} ({len(info)} IP 已查)")
        time.sleep(IP_API_BATCH_RPS_INTERVAL)
    return info


def offline_ip_lookup(ip: str, country_reader, asn_reader) -> tuple:
    """GeoLite2 离线查询 → (country, asn, org)"""
    country, asn, org = None, None, None
    try:
        c = country_reader.get(ip)
        if c and c.get("country", {}).get("iso_code"):
            country = c["country"]["iso_code"]
    except Exception:
        pass
    try:
        a = asn_reader.get(ip)
        if a:
            asn = a.get("autonomous_system_number")
            org = a.get("autonomous_system_organization", "")
    except Exception:
        pass
    return country, asn, org


def get_rdns(ip: str) -> str:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def classify_network_type(ip: str, country: str, asn, org: str, ip_api_rec: dict = None) -> tuple:
    """
    返回 (net_type, confidence):
      net_type ∈ {datacenter, residential, mobile, cdn, unknown}
    优先级: ip-api.com hosting/mobile 字段 > CDN 网段 > ASN 白/黑名单 > 名称关键词
    """
    ip_str = str(ip)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown", 0

    # 1) CDN / Anycast 网段 (硬判据)
    for net in CLOUDFLARE_IP_NETWORKS:
        if ip_obj in net:
            return "cdn", 100
    for net in CDN_IP_NETWORKS_EXTRA:
        if ip_obj in net:
            return "cdn", 95

    asn_int = None
    if isinstance(asn, int):
        asn_int = asn
    elif isinstance(asn, str) and asn:
        m = re.match(r"AS(\d+)", asn)
        if m:
            asn_int = int(m.group(1))

    org_lower = (org or "").lower()
    hosting_flag = False
    mobile_flag = False
    proxy_flag = False

    # 2) ip-api.com 在线字段 (最高可信)
    if ip_api_rec:
        hosting_flag = bool(ip_api_rec.get("hosting"))
        mobile_flag = bool(ip_api_rec.get("mobile"))
        proxy_flag = bool(ip_api_rec.get("proxy"))
        rec_asn = ip_api_rec.get("as") or ""
        m = re.match(r"AS(\d+)", str(rec_asn))
        if m and asn_int is None:
            asn_int = int(m.group(1))
        org_lower = (ip_api_rec.get("asname") or ip_api_rec.get("org") or org_lower).lower()

    if hosting_flag:
        return "datacenter", 90
    # ★ proxy/VPN/Tor 出口标志 (ip-api) — 硬否决家宽/民用
    # 实测 AS62610 Zenlayer (收购 speakeasy DSL legacy 段): hosting=false 但 proxy=true
    # 此类"机房收购家宽段"是假家宽主要形态, rDNS 带 dsl/pppoe 也不能信
    if proxy_flag:
        return "datacenter", 88
    if mobile_flag:
        return "mobile", 85

    # 3) ASN 白/黑名单
    if asn_int:
        if asn_int in DATACENTER_ASNS:
            return "datacenter", 80
        if asn_int in RESIDENTIAL_ASNS:
            return "residential", 82

    # 4) ISP 名称关键词
    if org_lower:
        for kw in IDC_NAME_PATTERNS:
            if kw in org_lower:
                return "datacenter", 70
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in org_lower:
                return "residential", 70

    # 5) rDNS 兜底
    rdns = get_rdns(ip_str)
    if rdns:
        for kw in IDC_NAME_PATTERNS:
            if kw in rdns:
                return "datacenter", 60
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in rdns:
                return "residential", 60

    return "unknown", 30


# ═══════════════════════════════════════════N═══════════════════════
# 节点 → 各客户端配置转换
# ═══════════════════════════════════════════N═══════════════════════

def outbound_to_clash(node: dict, name: str) -> dict:
    """sing-box outbound → Clash (Meta/mihomo) proxy dict"""
    t = node.get("type")
    server, port = node["server"], node["server_port"]
    proxy = {"name": name, "server": server, "port": port, "udp": True}

    if t == "vless":
        proxy["type"] = "vless"
        proxy["uuid"] = node["uuid"]
        if node.get("flow"):
            proxy["flow"] = node["flow"]
        tls = node.get("tls") or {}
        if tls.get("reality"):
            proxy["tls"] = True
            proxy["reality-opts"] = {"public-key": tls["reality"]["public_key"]}
            if tls["reality"].get("short_id"):
                proxy["reality-opts"]["short-id"] = tls["reality"]["short_id"]
            proxy["servername"] = tls.get("server_name") or server
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        elif tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
            elif transport["type"] == "httpupgrade":
                proxy["network"] = "httpupgrade"
                proxy["httpupgrade-opts"] = {"path": transport.get("path", "/"),
                                              "headers": {"Host": transport.get("host", "")}}
    elif t == "vmess":
        proxy["type"] = "vmess"
        proxy["uuid"] = node["uuid"]
        proxy["alterId"] = node.get("alter_id", 0)
        proxy["cipher"] = "auto"
        tls = node.get("tls") or {}
        if tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
    elif t == "trojan":
        proxy["type"] = "trojan"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
    elif t == "shadowsocks":
        proxy["type"] = "ss"
        proxy["cipher"] = node["method"]
        proxy["password"] = node["password"]
    elif t == "hysteria2":
        proxy["type"] = "hysteria2"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        if node.get("obfs"):
            proxy["obfs"] = node["obfs"].get("type")
            proxy["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            proxy["ports"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
    elif t == "tuic":
        proxy["type"] = "tuic"
        proxy["uuid"] = node["uuid"]
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        proxy["congestion-controller"] = node.get("congestion_control", "bbr")
        proxy["udp-relay-mode"] = node.get("udp_relay_mode", "native")
        if tls.get("alpn"):
            proxy["alpn"] = tls["alpn"]
    elif t == "anytls":
        proxy["type"] = "anytls"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
    else:
        return None
    return proxy


def outbound_to_v2ray_link(node: dict, name: str) -> str:
    """sing-box outbound → v2rayN 兼容 URI"""
    t = node.get("type")
    # 端口跳跃节点 (hy2 mport): 无 server_port 时取 server_ports 首区间起始端口
    if "server_port" in node:
        port = node["server_port"]
    elif node.get("server_ports"):
        port = int(str(node["server_ports"][0]).split(":")[0])
    else:
        return ""
    server = node["server"]
    tls = node.get("tls") or {}
    transport = node.get("transport") or {}

    if t == "vmess":
        ttype = transport.get("type", "tcp")
        data = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": node["uuid"], "aid": str(node.get("alter_id", 0)),
            "scy": "auto", "net": ttype,
            "type": "none",
            "host": "", "path": "",
            "tls": "tls" if tls.get("enabled") else "",
            "sni": tls.get("server_name", ""),
        }
        if ttype == "ws":
            if transport.get("path"):
                data["path"] = transport["path"]
            if (transport.get("headers") or {}).get("Host"):
                data["host"] = transport["headers"]["Host"]
            if transport.get("max_early_data"):
                data["path"] = (data["path"] or "") + f"?ed={transport['max_early_data']}"
        elif ttype == "grpc":
            if transport.get("service_name"):
                data["path"] = transport["service_name"]
        elif ttype == "http":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = ",".join(transport["host"])
        elif ttype == "httpupgrade":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = transport["host"]
        return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
    if t == "vless":
        q = {}
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "http":
                if transport.get("host"):
                    q["host"] = ",".join(transport["host"])
                if transport.get("path"):
                    q["path"] = transport["path"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        if tls.get("reality"):
            q["security"] = "reality"
            q["pbk"] = tls["reality"]["public_key"]
            q["sid"] = tls["reality"].get("short_id", "")
            q["fp"] = (tls.get("utls") or {}).get("fingerprint", "chrome")
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
        elif tls.get("enabled"):
            q["security"] = "tls"
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
            if tls.get("alpn"):
                q["alpn"] = ",".join(tls["alpn"])
            if tls.get("utls"):
                q["fp"] = tls["utls"].get("fingerprint", "chrome")
            if tls.get("insecure"):
                q["allowInsecure"] = "1"
        if node.get("flow"):
            q["flow"] = node["flow"]
        query = urllib.parse.urlencode(q)
        return f"vless://{node['uuid']}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "trojan":
        q = {"security": "tls"}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("alpn"):
            q["alpn"] = ",".join(tls["alpn"])
        if (tls.get("utls") or {}).get("fingerprint"):
            q["fp"] = tls["utls"]["fingerprint"]
        if tls.get("insecure"):
            q["allowInsecure"] = "1"
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        query = urllib.parse.urlencode(q)
        return f"trojan://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "shadowsocks":
        # SIP002: userinfo = urlsafe-base64(method:password), ★ 必须保留 padding ("=")
        # 实测: rstrip("=") 砍 padding 后 v2rayN 解析失败 (无 padding 的畸形 base64)
        # urlsafe 字母表 (A-Za-z0-9-_) + "=" 均为 URI 合法字符, 不需再 quote (quote 反而破坏 "=")
        userinfo = base64.urlsafe_b64encode(
            f"{node['method']}:{node['password']}".encode()).decode()
        return f"ss://{userinfo}@{server}:{port}#{urllib.parse.quote(name)}"
    if t == "hysteria2":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        if node.get("obfs"):
            q["obfs"] = node["obfs"].get("type", "salamander")
            q["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            q["mport"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
        query = urllib.parse.urlencode(q)
        return f"hysteria2://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "tuic":
        q = {
            "congestion_control": node.get("congestion_control", "bbr"),
            "udp_relay_mode": node.get("udp_relay_mode", "native"),
            "alpn": ",".join((tls.get("alpn") or ["h3"])),
        }
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["allow_insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"tuic://{urllib.parse.quote(node['uuid'])}:{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "anytls":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"anytls://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    return ""


def outbound_to_singbox(node: dict, name: str) -> dict:
    n = dict(node)
    n["tag"] = name
    return n


# ═══════════════════════════════════════════N═══════════════════════
# 分类 + 导出
# ═══════════════════════════════════════════N═══════════════════════

def scamalytics_fraud_score(ip: str) -> int:
    """Scamalytics 免费风控评分 (HTML 抓取, subs-check 同款方案)
    返回 0-100: 越高越危险; 失败返回 -1 (不参与判定)"""
    try:
        r = DIRECT_SESSION.get(f"https://scamalytics.com/ip/{ip}", timeout=10)
        if r.status_code != 200:
            return -1
        m = re.search(r"Fraud Score:\s*(\d+)", r.text)
        return int(m.group(1)) if m else -1
    except Exception:
        return -1


def ipapi_is_verify(ip: str) -> dict:
    """ipapi.is 免费交叉源 (1000 req/天, 无 key)
    实测对 AS62610 Zenlayer (收购 speakeasy DSL 段伪装家宽) 能给出
    company=Bunny Communications; 对真家宽 (SK Broadband) 给运营商名。
    仅用其 company/asn 字段做家宽候选的二次否决。失败返回 {}"""
    try:
        r = DIRECT_SESSION.get(f"https://api.ipapi.is/?q={ip}", timeout=10)
        if r.status_code != 200:
            return {}
        j = r.json()
        return {"company": j.get("company") or "", "asn": j.get("asn") or "",
                "country": j.get("country") or ""}
    except Exception:
        return {}


def classify_and_export(test_results: list):
    print("[*] 出口 IP 情报与分类 ...")
    # 收集全部出口 IP
    all_exit_ips = []
    seen_ip = set()
    no_exit_ip = []
    for r in test_results:
        if r["exit_ip"] and r["exit_ip"] not in seen_ip:
            seen_ip.add(r["exit_ip"])
            all_exit_ips.append(r["exit_ip"])
    print(f"[*] 待查询出口 IP: {len(all_exit_ips)} 个 (ip-api.com 批量 {len(test_results)} 节点)")

    ip_api_info = {}
    scam_scores = {}
    if all_exit_ips:
        try:
            est_batches = (len(all_exit_ips) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
            print(f"[*] ip-api 批量: {est_batches} 批 × ~4.2s ≈ {est_batches * 4.2:.0f}s (免费限 15 req/min, 请耐心) ...")
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
            print(f"[+] ip-api.com 批量情报: {len(ip_api_info)}/{len(all_exit_ips)}")
        except Exception as e:
            print(f"[!] ip-api 批量失败, 将全量走离线: {e}")

    country_reader = asn_reader = None
    try:
        country_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "Country.mmdb"))
        asn_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "ASN.mmdb"))
    except Exception as e:
        print(f"[!] MaxMind 数据库打开失败: {e}")

    nodes = []
    for r in test_results:
        exit_ip = r["exit_ip"]
        online_country = r.get("exit_country_online")
        country = online_country
        asn, org = r.get("exit_asn_online"), r.get("exit_asn_org_online")
        if isinstance(asn, int):
            pass
        elif isinstance(asn, str):
            m = re.match(r"AS(\d+)", asn)
            asn = int(m.group(1)) if m else None

        # 在线情报缺失 → 离线 mmdb 兜底
        if country_reader and (not country or not asn):
            off_c, off_asn, off_org = offline_ip_lookup(exit_ip, country_reader, asn_reader)
            country = country or off_c
            asn = asn or off_asn
            org = org or off_org

        # ★ 出口 IP 查不到国家 (云内网/中转隧道) → 回退用入口服务器 IP 定位国家
        #    (中转节点出口常是内网地址, mmdb 也查不到; 入口国 ≠ 出口国但至少给用户可用地区)
        if (not country or country in ("OTHER", "ZZ")) and r.get("server"):
            srv_ip = r["server"] if is_ip_literal(r["server"]) else resolve_host(r["server"])
            if srv_ip and country_reader:
                off_c, srv_asn, srv_org = offline_ip_lookup(srv_ip, country_reader, asn_reader)
                if off_c and off_c not in ("OTHER", "ZZ"):
                    country = off_c
                    asn, org = asn or srv_asn, org or srv_org

        rec = ip_api_info.get(exit_ip, {})
        net_type, confidence = classify_network_type(
            exit_ip, country, asn, org, rec or None)

        # 无真实出口 IP 的节点: 国家未知, 不入家宽区
        if not exit_ip:
            country = country or "OTHER"

        nodes.append({
            "raw": r["raw"],
            "server": r["server"],
            "port": r["port"],
            "proto": r["proto"],
            "outbound": r.get("outbound"),
            "country": (country or "OTHER").upper(),
            "net_type": net_type,
            "confidence": confidence,
            "exit_ip": exit_ip,
            "asn": asn,
            "org": org,
            "isp": r.get("exit_isp_online") or (rec.get("isp") if rec else ""),
            "latency_ms": r["latency_ms"],
            "speed_bps": r["speed_bps"],
            "mitm_risk": r["mitm_risk"],
            "is_stalled": r["is_stalled"],
        })

    if country_reader:
        country_reader.close()
    if asn_reader:
        asn_reader.close()

    # ── 风险过滤 ──
    # MITM 劫持节点: 高危, 直接丢弃 (204 能通但证书被劫持 = 中间人)
    safe_nodes = [n for n in nodes if not n["mitm_risk"]]
    mitm_dropped = len(nodes) - len(safe_nodes)
    # 断流节点已无 (在 liveness 阶段淘汰), 但 double-check
    safe_nodes = [n for n in safe_nodes if not n["is_stalled"]]
    print(f"[*] MITM 劫持高风险节点已剔除: {mitm_dropped}")

    # ── Scamalytics 风控评分 (免费 HTML, 逐个; 只查家宽候选 + 抽样普通节点) ──
    # 家宽候选: 全查 (宁缺毋滥); 普通节点: 每 IP 查一次 (通常 <= 出口 IP 数)
    scam_candidates = set()
    for n in safe_nodes:
        if n["net_type"] in ("residential", "mobile") and n["exit_ip"]:
            scam_candidates.add(n["exit_ip"])
    if scam_candidates:
        print(f"[*] Scamalytics 风控评分: 查询 {len(scam_candidates)} 个家宽候选出口 IP ...")
        def _scam(ip):
            return ip, scamalytics_fraud_score(ip)
        with ThreadPoolExecutor(max_workers=6) as ex:
            for ip, score in ex.map(_scam, scam_candidates):
                scam_scores[ip] = score
        got = sum(1 for v in scam_scores.values() if v >= 0)
        print(f"[+] Scamalytics 评分获得: {got}/{len(scam_candidates)}")

    # ── ipapi.is 交叉核验 (只查家宽候选, 免费 1000 次/天) ──
    # ip-api 判 hosting/proxy 也有漏 (伪装家宽: 收购 DSL 段的云边网络)。
    # ipapi.is 独立数据源: company 含 IDC 词 → 否决家宽
    ipapi_verify = {}
    verify_candidates = set()
    for n in safe_nodes:
        if n["net_type"] in ("residential", "mobile") and n["exit_ip"]:
            verify_candidates.add(n["exit_ip"])
    if verify_candidates:
        print(f"[*] ipapi.is 交叉核验: {len(verify_candidates)} 个家宽候选 ...")
        def _verify(ip):
            return ip, ipapi_is_verify(ip)
        with ThreadPoolExecutor(max_workers=4) as ex:
            for ip, info in ex.map(_verify, verify_candidates):
                ipapi_verify[ip] = info
        # 否决: company/asn 含机房词
        vetoed = 0
        for n in safe_nodes:
            if n["net_type"] not in ("residential", "mobile"):
                continue
            info = ipapi_verify.get(n["exit_ip"]) or {}
            comp_asn = (info.get("company", "") + " " + info.get("asn", "")).lower()
            if any(kw in comp_asn for kw in (
                "zenlayer", "bunny", "cloudflare", "akamai", "fastly",
                "amazon", "google llc", "microsoft", "digitalocean", "vultr",
                "hetzner", "ovh", "contabo", "leaseweb", "datacamp",
                "serverius", "clouvider", "m247", "gcore", "g-core",
                "choopa", "linode", "alibaba", "tencent", "huawei cloud",
            )):
                n["net_type"] = "datacenter"
                n["confidence"] = 85
                vetoed += 1
        if vetoed:
            print(f"[*] ipapi.is 否决假家宽: {vetoed} 个 (云商收购家宽段伪装)")

    # 风险分 >= 75 的家宽候选降级为普通 (fraud 池/被滥用 IP 绝不入家宽区)
    downgraded = 0
    for n in safe_nodes:
        sc = scam_scores.get(n["exit_ip"], -1)
        n["fraud_score"] = sc
        if n["net_type"] in ("residential", "mobile") and sc >= 75:
            n["net_type"] = "datacenter"  # 高 fraud 分: 大概率代理池滥用 IP
            n["confidence"] = 60
            downgraded += 1
    if downgraded:
        print(f"[*] 高 fraud 分 (≥75) 家宽候选降级: {downgraded} 个")

    # ── 去重 (同出口IP+端口 只留最快) ──
    best_by_key = {}
    for n in safe_nodes:
        key = f"{n['exit_ip']}:{n['port']}" if n["exit_ip"] else f"{n['server']}:{n['port']}|{n['raw'][:64]}"
        cur = best_by_key.get(key)
        if not cur or n["latency_ms"] < cur["latency_ms"]:
            best_by_key[key] = n
    unique_nodes = list(best_by_key.values())
    dup_dropped = len(safe_nodes) - len(unique_nodes)
    print(f"[*] 去重: {len(safe_nodes)} → {len(unique_nodes)} (剔除重复 {dup_dropped})")

    # 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
    # ★ 链式复测 (chain_retest) 双跳失败的家宽候选 → 不进家宽专区 (降级普通)
    chain_failed_raws = set()
    for r in test_results:
        if r.get("_chain_failed"):
            chain_failed_raws.add(r.get("raw"))
    residential = []
    res_seen_ip = set()
    for n in unique_nodes:
        if n["net_type"] in ("residential", "mobile") and n["confidence"] >= 60:
            if n.get("raw") in chain_failed_raws:
                n["net_type"] = "datacenter"
                n["confidence"] = 70
                continue
            if n["exit_ip"] and n["exit_ip"] not in res_seen_ip:
                res_seen_ip.add(n["exit_ip"])
                residential.append(n)
    # fraud 分极高 (≥90) 的节点整体剔除 (任何区都不要)
    before_total = len(unique_nodes)
    unique_nodes = [n for n in unique_nodes if not (0 <= n.get("fraud_score", -1) >= 90)]
    residential = [n for n in residential if not (0 <= n.get("fraud_score", -1) >= 90)]
    if len(unique_nodes) < before_total:
        print(f"[*] 极高危节点 (fraud≥90) 剔除: {before_total - len(unique_nodes)} 个")

    non_residential = [n for n in unique_nodes if n not in residential]
    print(f"[*] 家宽/移动网络节点: {len(residential)} | 普通(机房/CDN): {len(non_residential)}")

    # 排序: 家宽在前, 延迟升序
    unique_nodes.sort(key=lambda x: (0 if x in residential else 1, x["latency_ms"]))
    residential.sort(key=lambda x: x["latency_ms"])
    non_residential.sort(key=lambda x: x["latency_ms"])
    # ★ 链式复测双跳失败的家宽 → 降级普通区 (v2rayN 链式场景不可靠)
    #    保留在总订阅/国家订阅里 (直连场景仍可用), 只是退出家宽专区

    # 重建 outbound (测活阶段的 outbound 已验证可用); 剥离测试专用字段 (detour 等绝不入订阅)
    for n in unique_nodes:
        parsed = parse_node_uri(n["raw"])
        if parsed:
            ob = parsed[0]
            ob.pop("detour", None)
            n["outbound"] = ob
        else:
            n["outbound"] = None

    return unique_nodes, residential, non_residential


def make_node_name(item, idx, force_residential=False):
    cc = item["country"]
    flag = get_country_flag(cc)
    cname = COUNTRY_NAMES.get(cc, cc)
    is_res = item["net_type"] in ("residential", "mobile") and (item["confidence"] >= 60 or force_residential)
    tag = ""
    if is_res:
        tag = " (家宽)" if item["net_type"] == "residential" else " (移动家宽)"
    # Scamalytics 风控分: 高风险节点名内标注 (R分数), 低危不标 (保持简洁)
    fraud = item.get("fraud_score", -1)
    risk_tag = f" R{fraud}" if 0 <= fraud < 75 and fraud >= 40 else (" ⚠R" if fraud >= 75 else "")
    return f"{flag} {cname} {idx:02d}{tag}{risk_tag} - xiaohe"


def export_all(unique_nodes, residential, non_residential):
    ensure_directories()

    def build_group(nodes_list, force_res=False):
        links, proxies, sb_nodes = [], [], []
        for idx, item in enumerate(nodes_list, start=1):
            name = make_node_name(item, idx, force_res)
            ob = item["outbound"]
            if not ob:
                continue
            links.append(outbound_to_v2ray_link(ob, name))
            cp = outbound_to_clash(ob, name)
            if cp:
                proxies.append(cp)
            sb_nodes.append(outbound_to_singbox(ob, name))
        return links, proxies, sb_nodes

    # 1) 全量
    all_links, all_proxies, all_sb = build_group(unique_nodes)
    with open(os.path.join(OUTPUT_DIR, "v2ray.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(all_links).encode()).decode())
    export_clash_yaml(all_proxies, os.path.join(OUTPUT_DIR, "clash.yaml"))
    export_singbox_json(all_sb, os.path.join(OUTPUT_DIR, "singbox.json"))

    # 2) 家宽总订阅
    res_links, res_proxies, res_sb = build_group(residential, force_res=True)
    with open(os.path.join(OUTPUT_DIR, "residential.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(res_links).encode()).decode())
    if res_proxies:
        export_clash_yaml(res_proxies, os.path.join(OUTPUT_DIR, "residential-clash.yaml"))
        export_singbox_json(res_sb, os.path.join(OUTPUT_DIR, "residential-singbox.json"))
    else:
        for fn in ("residential-clash.yaml", "residential-singbox.json"):
            p = os.path.join(OUTPUT_DIR, fn)
            if os.path.exists(p):
                os.remove(p)

    # 3) 按国家 - 普通区
    shutil.rmtree(COUNTRY_DIR, ignore_errors=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    by_cc = {}
    for n in non_residential:
        by_cc.setdefault(n["country"], []).append(n)
    for cc, lst in by_cc.items():
        l, p, s = build_group(lst)
        with open(os.path.join(COUNTRY_DIR, f"{cc}.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(l).encode()).decode())
        export_clash_yaml(p, os.path.join(COUNTRY_DIR, f"clash-{cc}.yaml"))
        export_singbox_json(s, os.path.join(COUNTRY_DIR, f"singbox-{cc}.json"))

    # 4) 按国家 - 家宽区
    shutil.rmtree(RESIDENTIAL_COUNTRY_DIR, ignore_errors=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
    res_by_cc = {}
    for n in residential:
        res_by_cc.setdefault(n["country"], []).append(n)
    for cc, lst in res_by_cc.items():
        l, p, s = build_group(lst, force_res=True)
        with open(os.path.join(RESIDENTIAL_COUNTRY_DIR, f"{cc}.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(l).encode()).decode())
        export_clash_yaml(p, os.path.join(RESIDENTIAL_COUNTRY_DIR, f"clash-{cc}.yaml"))
        export_singbox_json(s, os.path.join(RESIDENTIAL_COUNTRY_DIR, f"singbox-{cc}.json"))

    print(f"[*] 导出完毕: 全量 {len(all_links)} | 家宽 {len(res_links)}")
    return len(all_links), len(res_links)


def export_clash_yaml(clash_proxies, filepath):
    names = [p["name"] for p in clash_proxies]
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "PROXIES", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "url": "https://www.gstatic.com/generate_204",
             "interval": 300, "proxies": names},
        ],
        "rules": ["MATCH,PROXIES"],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


def export_singbox_json(sb_nodes, filepath):
    names = [n["tag"] for n in sb_nodes]
    outbounds = sb_nodes + [
        {"type": "selector", "tag": "select", "outbounds": ["auto"] + names},
        {"type": "urltest", "tag": "auto", "outbounds": names,
         "url": "https://www.gstatic.com/generate_204"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    config = {"log": {"level": "warn"},
              "outbounds": outbounds}
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════N═══════════════════════
# README 生成
# ═══════════════════════════════════════════N═══════════════════════

def update_readme(total_count, res_count):
    repo_name = os.environ.get("GITHUB_REPOSITORY", "hezhanleiok/freesub").strip()
    cache_bust = int(time.time())
    # 私有化部署 Worker 脚本里的仓库参数 (默认值兜底)
    try:
        owner, repo = repo_name.split("/", 1)
    except ValueError:
        owner, repo = "hezhanleiok", "freesub"

    def count_file(path):
        if not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read().strip()
                if not c:
                    return 0
                decoded = base64.b64decode(c).decode("utf-8", errors="ignore")
                return len([ln for ln in decoded.splitlines() if ln.strip()])
        except Exception:
            return 0

    res_counts, normal_counts = {}, {}
    for d, store in ((RESIDENTIAL_COUNTRY_DIR, res_counts), (COUNTRY_DIR, normal_counts)):
        if os.path.exists(d):
            for fn in os.listdir(d):
                if fn.endswith(".txt"):
                    cnt = count_file(os.path.join(d, fn))
                    if cnt > 0:
                        store[fn[:-4]] = cnt

    def table_rows(counts, sub):
        rows = []
        for cc in sorted(counts, key=lambda x: counts[x], reverse=True):
            flag = get_country_flag(cc)
            name = COUNTRY_NAMES.get(cc, cc)
            cnt = counts[cc]
            v2 = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/{cc}.txt?v={cache_bust}) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/{cc}.txt)"
            cl = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/clash-{cc}.yaml?v={cache_bust}) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/clash-{cc}.yaml)"
            sb = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/singbox-{cc}.json?v={cache_bust}) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/singbox-{cc}.json)"
            rows.append(f"| {flag} {name} | {cnt} | {v2} | {cl} | {sb} |")
        return "\n".join(rows) if rows else "| 暂无可用节点 | 0 | - | - | - |"

    res_table = table_rows(res_counts, "residential-by-country")
    normal_table = table_rows(normal_counts, "by-country")

    readme = f"""# 🚀 免费节点自动测活订阅池 (含真实家宽/住宅IP甄选)

> 👤 **定制规范命名**: 所有订阅节点均重命名为 `国旗 地区 序号 (家宽) - xiaohe`
> ⚡ **真实可用保障**: 所有节点由 `sing-box v{SINGBOX_VERSION}` 内核建立实际代理隧道, 完成真实 HTTPS 双向传输握手 + 出口 IP 穿透验证 + Cloudflare 限速下载断流检测 + TLS 证书校验 (MITM 劫持识别), 拒绝虚假通畅、断流节点与高危劫持节点。
> 🛡️ **全协议支持**: VLESS (Reality/Vision) · VMESS · Trojan · Shadowsocks · Hysteria2 · TUIC · AnyTLS

---

## 📌 全部节点总订阅链接

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 订阅直链 (国内直连) | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/clash.yaml?v={cache_bust}) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/v2ray.txt?v={cache_bust}) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/v2ray.txt) |
| 📦 **sing-box (JSON 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/singbox.json?v={cache_bust}) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/singbox.json) |

---

## 🏠 按照家宽分类节点订阅 (住宅 IP 专区)

> 家宽判定六重信号: ① ip-api.com `hosting` 字段 ② `mobile` 移动网络字段 ③ Cloudflare/主流 CDN Anycast 网段比对 ④ MaxMind GeoLite2 ASN 白/黑名单 (覆盖 60+ 国家主流民用运营商) ⑤ rDNS/ISP 名称特征 ⑥ Scamalytics 风控评分复核 (fraud ≥75 降级、≥90 剔除)。排除所有云主机/数据中心/CDN 任播, 保留真实民用宽带与移动网络。

| 家宽地区 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{res_table}

---

## 🗺️ 按照国家分类节点订阅 (非家宽/数据中心节点)

| 地区/国家 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{normal_table}

---

## 🔒 私有仓库（Private）无感免翻订阅方案 (基于 Cloudflare Workers)

> 如果你希望将本 GitHub 仓库设置为 **Private (私有仓库)** 保护节点资产，外部客户端无法直接拉取原生 Raw 或公共 CDN 链接，可以通过以下 Cloudflare Worker 搭建轻量级私密网关反代：

### 1. 获取 GitHub 永久个人令牌 (PAT)
1. 进入 GitHub -> **Settings** -> **Developer Settings** -> **Personal access tokens (classic)**。
2. 点击 **Generate new token (classic)**，勾选 `repo` 权限，有效期设为 `No expiration`（永不过期）。
3. 复制保存生成的以 `ghp_` 开头的 Token。

### 2. 部署 Cloudflare Worker
登录 Cloudflare Dashboard，创建一个新的 Worker，复制以下脚本粘贴并部署（把 `OWNER`/`REPO`/`GITHUB_TOKEN` 改成你自己的）：

```javascript
export default {{
  async fetch(request) {{
    const GITHUB_TOKEN = "ghp_你的GitHub永久访问令牌";
    const OWNER = "{owner}";
    const REPO = "{repo}";
    const BRANCH = "main";

    const url = new URL(request.url);
    const filePath = "output" + url.pathname;
    const ghUrl = "https://raw.githubusercontent.com/" + OWNER + "/" + REPO + "/" + BRANCH + "/" + filePath;

    const res = await fetch(ghUrl, {{
      headers: {{
        "Authorization": "token " + GITHUB_TOKEN,
        "User-Agent": "Cloudflare-Worker"
      }}
    }});

    if (!res.ok) {{
      return new Response("Not Found", {{ status: 404 }});
    }}

    return new Response(await res.text(), {{
      headers: {{
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache"
      }}
    }});
  }}
}}
```

### 3. 私有订阅链接映射方式
部署后 Worker 会分配一个专属域名（例如 `my-sub.yourname.workers.dev`），你的客户端可以直接无感订阅：
* **总 V2RayN 订阅**: `https://你的域名.workers.dev/v2ray.txt`
* **总 Clash 订阅**: `https://你的域名.workers.dev/clash.yaml`
* **总 sing-box 订阅**: `https://你的域名.workers.dev/singbox.json`
* **台湾家宽 V2RayN**: `https://你的域名.workers.dev/residential-by-country/TW.txt`
* **香港家宽 Clash**: `https://你的域名.workers.dev/residential-by-country/clash-HK.yaml`
* **日本家宽 sing-box**: `https://你的域名.workers.dev/residential-by-country/singbox-JP.json`

---

## ⭐ 项目热度

[![Star History Chart](https://api.star-history.com/svg?repos={repo_name}&type=Date)](https://star-history.com/#{repo_name}&Date)

---

## 🛠️ 项目使用说明
1. **自动更新机制**：GitHub Actions 每 6 小时全自动运行并刷新上述全部订阅与数据。
2. **测活标准**：节点必须通过 ① 端口预检 ② sing-box 实际隧道 3 个 generate_204 探测 ③ 真实出口 IP 穿透获取 ④ Cloudflare 5MB 限时下载 (吞吐 ≥ 70KB/s) ⑤ TLS 证书校验非 MITM, 方可入库。
3. **多客户端兼容**：Clash / v2rayN / sing-box 全格式订阅。
"""
    with open(os.path.join(BASEDIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)
    print(f"[+] README.md 更新完毕: 总节点 {total_count}, 家宽 {res_count}")


# ═══════════════════════════════════════════N═══════════════════════
# 主流程
# ═══════════════════════════════════════════N═══════════════════════

def main():
    t_start = time.time()
    print(f"==== 免费节点测活订阅池 v2 · 启动于 {datetime.now(timezone.utc).isoformat()} ====")
    ensure_directories()
    setup_environment()

    # 1. 抓取
    raw_nodes = fetch_raw_nodes()

    # 2. 解析
    candidates = []
    parse_fail = 0
    for uri in raw_nodes:
        parsed = parse_node_uri(uri)
        if not parsed:
            parse_fail += 1
            continue
        outbound, server, port, proto = parsed
        # 屏蔽占位/广告节点
        if BLACKLIST_NAME_HINTS.search(urllib.parse.unquote(uri.split("#", 1)[-1] if "#" in uri else "")):
            continue
        candidates.append((uri, outbound, server, port, proto))

    # 2.5 ★ 测前强去重 (凭据指纹去重: 同 凭据+目标+协议 只测一次, 结果回填全部重复节点)
    #     key = (server, port, proto, 凭据指纹): 凭据不同 → 服务端校验结果可能不同, 不可合并
    #     凭据指纹: uuid/password 各协议的核心身份字段 (vless uuid / vmess id+alterId /
    #               trojan password / ss 2022密钥 / hy2 auth / tuic uuid+passwd / anytls password)
    #     完全相同 = 同一节点被多源重复收录 (免费池常态, 30+ 份不同名字) → 只测一次
    def cred_fingerprint(outbound: dict, proto: str) -> str:
        try:
            if proto == "vless":
                return f"{outbound.get('uuid','')}"
            if proto == "vmess":
                return f"{outbound.get('uuid','') or outbound.get('user_id','')}"
            if proto == "trojan":
                return f"{outbound.get('password','')}"
            if proto == "shadowsocks":
                return f"{outbound.get('method','')}|{outbound.get('password','')}"
            if proto == "hysteria2":
                return f"{outbound.get('password','') or ''}|{outbound.get('server_ports','')}"
            if proto == "tuic":
                return f"{outbound.get('uuid','')}|{outbound.get('password','')}"
            if proto == "anytls":
                return f"{outbound.get('password','')}"
            return json.dumps({k: v for k, v in outbound.items()
                              if k in ("uuid", "password", "user_id", "method")}, sort_keys=True)
        except Exception:
            return ""  # 指纹失败 → 不合并 (宁慢不错)

    seen_keys, deduped, dup_count = {}, [], 0
    for item in candidates:
        uri, outbound, server, port, proto = item
        key = (server.lower() if server else "", port, proto, cred_fingerprint(outbound, proto))
        if key in seen_keys:
            seen_keys[key].append(uri)  # 记录重复 URI, 测活后回填
            dup_count += 1
        else:
            seen_keys[key] = [uri]
            deduped.append(item)
    if dup_count:
        print(f"[*] 测前去重(凭据指纹): {len(candidates)} → {len(deduped)} (剔除重复 {dup_count} — 结果将回填)")
    DEDUP_MAP = seen_keys  # 供测活后回填 (全局)
    candidates = deduped

    proto_stat = {}
    for _, _, _, _, p in candidates:
        proto_stat[p] = proto_stat.get(p, 0) + 1
    print(f"[*] 解析成功(去重后): {len(candidates)} | 失败 {parse_fail} | 协议分布 {proto_stat}")

    if not candidates:
        print("[!] 无可测节点 (订阅源全部失效?) — 保留上次 output, 不覆盖订阅文件")
        return

    # 3. 端口预检
    candidates = prefilter_candidates(candidates)

    # 4. 真实测活 (只测去重后的代表节点)
    test_results = run_liveness_test(candidates)

    # 4.5 ★ 重复节点结果回填: 同 凭据+目标 的重复 URI 继承测活结果 (凭据相同 → 服务端表现一致)
    if DEDUP_MAP:
        result_by_key = {}
        for r in test_results:
            key = ((r["server"] or "").lower(), r["port"], r["proto"])
            result_by_key[key] = r
        expanded = list(test_results)
        backfilled = 0
        # 反向索引: server:port:proto → 原始 fingerprint (从 DEDUP_MAP 的 key 直接继承)
        for key, uris in DEDUP_MAP.items():
            if len(uris) <= 1:
                continue
            # 用 key 的前三段 (server, port, proto) 找测活结果
            lookup = (key[0], key[1], key[2])
            r = result_by_key.get(lookup)
            if not r or not r.get("alive"):
                continue
            for extra_uri in uris[1:]:
                clone = dict(r)
                clone["raw"] = extra_uri
                expanded.append(clone)
                backfilled += 1
        if backfilled:
            print(f"[+] 重复节点回填: +{backfilled} (继承代表测活结果)")
        test_results = expanded

    # 5. ★ 家宽链式复测: 用最快存活节点做前置双跳复测家宽候选
    #    (模拟用户 v2rayN 链式场景, 双跳失败的家宽降级普通区 — 提高链式可用率)
    test_results = chain_retest(test_results)

    # 6. 分类 + 导出 (无真活节点时保留上次 output, 不写空订阅覆盖线上数据)
    if not test_results:
        print("[!] 全部节点测活失败 — 保留上次 output, 不覆盖订阅文件")
        return
    unique_nodes, residential, non_residential = classify_and_export(test_results)
    if not unique_nodes:
        print("[!] 分类后无存活节点 — 保留上次 output")
        return
    total, res = export_all(unique_nodes, residential, non_residential)
    update_readme(total, res)

    # ★ CDN 缓存刷新: jsdelivr 边缘节点缓存滞后导致 "CDN 订阅比 RAW 少节点"
    #    (实测 TW CDN=2 vs RAW=4, purge 后立即一致) — CI 每次跑完主动刷新
    try:
        repo_name = os.environ.get("GITHUB_REPOSITORY", "").strip()
        if repo_name and "/" in repo_name:
            purged, failed = 0, 0
            for f in glob.glob(os.path.join(BASEDIR, "output", "**", "*.*"), recursive=True):
                rel = os.path.relpath(f, BASEDIR).replace("\\", "/")
                try:
                    DIRECT_SESSION.get(
                        f"https://purge.jsdelivr.net/gh/{repo_name}@main/{rel}",
                        timeout=10)
                    purged += 1
                except Exception:
                    failed += 1
            print(f"[+] jsdelivr CDN 缓存刷新: {purged} 个文件 ({failed} 失败)")
    except Exception as e:
        print(f"[!] CDN 刷新跳过: {e}")

    # 统计报告
    elapsed = time.time() - t_start
    print("\n===== 运行报告 =====")
    print(f"总耗时: {elapsed:.0f}s | 抓取 {len(raw_nodes)} → 解析成功 {len(candidates)} → 真活 {len(test_results)} → 去重后 {len(unique_nodes)} → 家宽 {len(residential)}")
    by_type = {}
    for n in unique_nodes:
        by_type[n["net_type"]] = by_type.get(n["net_type"], 0) + 1
    print(f"节点类型分布: {by_type}")
    by_proto = {}
    for n in unique_nodes:
        by_proto[n["proto"]] = by_proto.get(n["proto"], 0) + 1
    print(f"协议分布(出库): {by_proto}")
    by_country = {}
    for n in unique_nodes:
        by_country[n["country"]] = by_country.get(n["country"], 0) + 1
    top_c = sorted(by_country.items(), key=lambda x: -x[1])[:10]
    print(f"国家 Top10: {top_c}")


if __name__ == "__main__":
    main()
