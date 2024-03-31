import re

def emailSpoofDetection(header, emailDomain):
    # Assign header and emailDomain to a variable 
    header = str(header);
    emailDomain = str(emailDomain);

    # Convert Gmail header object format to raw string 
    header = re.sub(r'\{\"name\"\:\"', '', header)
    header = re.sub(r'\"\,\"value\"\:\"', ': ', header)
    header = re.sub(r'\"\}\,', ', ', header)
    header = re.sub(r'^\[', '', header)
    header = re.sub(r'\"\}\]$', '', header)
    header = re.sub(r'\s+', ' ', header)

    # Remove new line characters, if any 
    header = re.sub(r'\n', ' ', header)
    header = re.sub(r'\t', ' ', header)

    match = []
    outcome = {}

    # Parse dkmin records in the header 
    dkimRegex = r'dkim\=(\S+)\sheader\.i\=\@(\S+)\s'
    dkim = {"result": [], "domain": []}
    match = re.findall(dkimRegex, header)
    for (r, d) in match:
        if r not in dkim["result"]:
            dkim["result"].append(r)
        if d not in dkim["domain"]:
            dkim["domain"].append(d)

    # Parse spf records in the header 
    spfRegex = r'spf\=(\S+).*?smtp\.mailfrom\=.*?\@(.*?)\;\s'
    spf = {"result": [], "domain": []}
    match = re.findall(spfRegex, header)
    for (r, d) in match:
        if r not in spf["result"]:
            spf["result"].append(r)
        if d not in spf["domain"]:
            spf["domain"].append(d)

    # Parse dmarc records in the header 
    dmarcRegex = r'dmarc\=(\S+)\s\(p\=\S+\s+sp\=\S+\s+dis\=\S+\)\s+header\.from\=(\S+)'
    dmarc = {"result": [], "domain": []}
    match = re.findall(dmarcRegex, header)
    for (r, d) in match:
        if r not in dmarc["result"]:
            dmarc["result"].append(r)
        if d not in dmarc["domain"]:
            dmarc["domain"].append(d)

    # Validate the result and domain name 
    if ("pass" in dkim["result"] and "pass" in spf["result"] and "pass" in dmarc["result"] and emailDomain in dkim["domain"]):
        outcome = {'validEmail': True}
    else:
        outcome = {'validEmail': False}
    return outcome

from emailSpoofDetection import emailSpoofDetection

# Retrieve email headers using Gmail REST API 
# https://developers.google.com/gmail/api/reference/rest/v1/users.messages/get

header = '''Delivered-To: haykanushasryan00@gmail.com
Received: by 2002:a05:7108:91d0:b0:37a:b6c0:a076 with SMTP id s16csp280711gdu;
        Tue, 26 Mar 2024 08:57:53 -0700 (PDT)
X-Google-Smtp-Source: AGHT+IE9/361VPGP7IM9bL6KOMN6SzPEnw8/8s3dkdTiG7jmbc5LcJ8Eb0A24mYnj45/tKs/SCHt
X-Received: by 2002:a25:d607:0:b0:dc6:23ac:9ef2 with SMTP id n7-20020a25d607000000b00dc623ac9ef2mr8551592ybg.19.1711468673035;
        Tue, 26 Mar 2024 08:57:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711468673; cv=none;
        d=google.com; s=arc-20160816;
        b=JcYulZiZw1Ce2YguJbKfbGUl1fJscpeYBbXRXkytFTpCcLO7M1dT5VLi77z0WiRkle
         C76ZlonMNJJCPLCRLrMCQhhGASlHNhTz1TM2QZ6ogmx30DFADjGM5Zm8aAjRiIPEjTJF
         oN7BO/VEDmNr04odPekbsnXgpZSjGW1yC78aMuhpr7bmqyDxmIcW7zgSFNJ252S/200u
         6BhIkStNn+zlm6RIarc+zABbrKdhqjxpT1wvZLr7bcNwRPV4/unId7tQCmF08CgmkVdO
         NqgYXby6PHSYd6Lpv+vif7DUY4WzNj03ErglMyuhpoRuKxuf1lfySimLgQk9evYwa1j8
         braw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:message-id:to:from:subject:mime-version
         :date:sender:dkim-signature:dkim-signature;
        bh=U8CRHU1tmP835kc20hD9TW6isMjqlUk6A60xQUB4TSc=;
        fh=RvaBUo3FAu3lvyA5Ze5CRU8iWaGsGlS/flYo0TJBoms=;
        b=r4ed8UzUtyfUHQBAm/NflVx/u/GT+nf8tjca7U5wtzW9qYPWSE6Rm9sm93g8BwnCZK
         SkJwqD2Fj7/qqygpPxkTH1T4o67YEEaGJNFEHOrK43J7RwFnAECsJFGA5SDrzDPsr1SI
         pR1OPaRys71BtQP8EQyVmNpQOW5hUQHxxB4DTPMoSAmNMpqrQGrghmnMJP5P6A5oc/xj
         ID8cYsUXOuKyHmZTDoAM1RwMiaO3QI44PmPPpkcSXoCJxHBR7MCzlIvmwB/HF5D43s3T
         Egc36eR/pZqU7UmJznbLE0vUeTGhOav/WdWETQHk997gc2lI+Jbdmke2h+1ujMv4TTyT
         W0Kg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@mg.acba.am header.s=k1 header.b=DsfBWfEr;
       dkim=pass header.i=@mailgun.org header.s=mg header.b=FZgoOtJl;
       spf=pass (google.com: domain of bounce+38ce03.1f61fb-haykanushasryan00=gmail.com@mg.acba.am designates 159.135.228.12 as permitted sender) smtp.mailfrom="bounce+38ce03.1f61fb-haykanushasryan00=gmail.com@mg.acba.am";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=acba.am
Return-Path: <bounce+38ce03.1f61fb-haykanushasryan00=gmail.com@mg.acba.am>
Received: from m228-12.mailgun.net (m228-12.mailgun.net. [159.135.228.12])
        by mx.google.com with UTF8SMTPS id y30-20020a25ad1e000000b00dd01c421122si2271730ybi.509.2024.03.26.08.57.52
        for <haykanushasryan00@gmail.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 08:57:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of bounce+38ce03.1f61fb-haykanushasryan00=gmail.com@mg.acba.am designates 159.135.228.12 as permitted sender) client-ip=159.135.228.12;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@mg.acba.am header.s=k1 header.b=DsfBWfEr;
       dkim=pass header.i=@mailgun.org header.s=mg header.b=FZgoOtJl;
       spf=pass (google.com: domain of bounce+38ce03.1f61fb-haykanushasryan00=gmail.com@mg.acba.am designates 159.135.228.12 as permitted sender) smtp.mailfrom="bounce+38ce03.1f61fb-haykanushasryan00=gmail.com@mg.acba.am";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=acba.am
DKIM-Signature: a=rsa-sha256; v=1; c=relaxed/relaxed; d=mg.acba.am; q=dns/txt; s=k1; t=1711468672; x=1711475872; h=Content-Transfer-Encoding: Content-Type: Message-Id: To: To: From: From: Subject: Subject: Mime-Version: Date: Sender: Sender: X-Feedback-Id; bh=U8CRHU1tmP835kc20hD9TW6isMjqlUk6A60xQUB4TSc=; b=DsfBWfErFMxra68Vwtrg56WzsLKQ+0kb6lmkMz5jeySrHxwdKNwnIRvtvMJDF5VON0WSIJ9Qd8cudxzl45mzDvTHPq60Li+LzbwxUC9O4EvKICXa/RapAMpt7kaffvTbkmrAZaq6Xa5QnVixXNsqUYqBGQYFHAANIC3hmK4dlUI=
DKIM-Signature: a=rsa-sha256; v=1; c=relaxed/relaxed; d=mailgun.org; q=dns/txt; s=mg; t=1711468672; x=1711475872; h=Content-Transfer-Encoding: Content-Type: Message-Id: To: To: From: From: Subject: Subject: Mime-Version: Date: Sender: Sender: X-Feedback-Id; bh=U8CRHU1tmP835kc20hD9TW6isMjqlUk6A60xQUB4TSc=; b=FZgoOtJlC2lVWg2EE2p9YKNv2zBpygYbqnLlJ1Vtuch3zZ9ImFBvo4UWZxKrj3jvSiLtZwZlBdYIfK7UkGNeyDiWTQw3D4/d5tZFDxGP1VXs/P4vMgLPtz7et5f4ZJnvl1/lQUtFx4Jpue2MYkt0MZOj1XGl8TfuLvRleXz+I6Q=
X-Feedback-Id: postmaster@mg.acba.am::6565d794ba7ffb7d122d2fbf:mailgun
X-Mailgun-Sending-Ip: 159.135.228.12
X-Mailgun-Sid: WyJkY2Q4MiIsImhheWthbnVzaGFzcnlhbjAwQGdtYWlsLmNvbSIsIjFmNjFmYiJd
Received: from <unknown> (<unknown> []) by 0a858b0ca671 with HTTP id 6602f080b4a297b7d7554b5e; Tue, 26 Mar 2024 15:57:52 GMT
Sender: info=inf.acba.am@mg.acba.am
Date: Tue, 26 Mar 2024 15:57:52 +0000
Mime-Version: 1.0
Subject: Ծանուցում սակագներում և պայմաններում փոփոխության վերաբերյալ
From: Acba bank OJSC <info@inf.acba.am>
To: haykanushasryan00@gmail.com
Message-Id: <20240326155752.4dba76df742307f1@mg.acba.am>
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html>
<html lang=3D"en">
<head>
    <meta charset=3D"UTF-8">
    <meta name=3D"viewport" content=3D"width=3Ddevice-width, initial-scale=
=3D1.0">
    <title>Document</title>
    <style>
        /* =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D Media Query =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D */
        @media screen and (max-width: 800px){
            .content{
                max-width: 500px !important;
            }

            .logo_green{
                width: 130px !important;
            }
        }
        @media screen and (max-width: 550px){
            .content{
                max-width: 400px !important;
            }

            .logo_container{
                margin: 10px auto !important;
            }

            .logo_green{
                width: 120px !important;
            }

            .header-text{
                font-size: 18px !important;
            }

            .text_content {
                font-size: 12px !important;
            }

            .footer{
                font-size: 11px !important;
            }
        }
        @media screen and (max-width: 450px){
            .content{
                max-width: 350px !important;
            }

            .logo_green{
                width: 110px !important;
            }

            .header-text{
                font-size: 16px !important;
            }

            .text_content {
                font-size: 11px !important;
            }

            .footer{
                font-size: 10px !important;
            }

            .btn_view{
                margin: 15px auto !important;
            }
        }
        @media screen and (max-width: 350px){
            .content{
                max-width: 300px !important;
            }

            .logo_container{
                margin: 5px auto !important;
            }

            .logo_green{
                width: 100px !important;
            }

            .header-text{
                font-size: 15px !important;
            }

            .text_content {
                font-size: 10px !important;
            }

            .footer{
                font-size: 9px !important;
            }

            .btn_view{
                margin: 10px auto !important;
            }
        }
    </style>
</head>


<body style=3D"padding: 0; margin: 0;box-sizing: border-box;"><img src=3D"h=
ttps://sapapp1002.acbaca.local:443/sap/public/cuan/link/001/DA339CD2CED4C7C=
8D4DD96ADA3240C5C2CED0C06/pixel.gif" WIDTH=3D"1" HEIGHT=3D"1" BORDER=3D"0" =
ALT=3D"" /><!--[if mso]><table border=3D"0" cellpadding=3D"0" cellspacing=
=3D"0" align=3D"left" style=3D"mso-table-lspace:0pt;  mso-table-rspace:0pt;=
 border-collapse: collapse; width: 100%"><tr><td style=3D"width: 100%;"><![=
endif]--><div style=3D"float: left; width: 100%" class=3D"sapMktBlock"><div=
 class=3D"content" style=3D"background-color: white; max-width: 600px; marg=
in: 0 auto;">
<div class=3D"logo_container" style=3D"margin: 15px 0;"></div>
<div class=3D"content-holder">
<div style=3D"width: 85%; margin: 0 auto;">
<p style=3D"text-align: left;">=D5=80=D5=A1=D6=80=D5=A3=D5=A5=D5=AC=D5=AB =
=D6=84=D5=A1=D6=80=D5=BF=D5=A1=D5=BA=D5=A1=D5=B6, <br /><br />=D5=8F=D5=A5=
=D5=B2=D5=A5=D5=AF=D5=A1=D6=81=D5=B6=D5=B8=D6=82=D5=B4 =D5=A5=D5=B6=D6=84, =
=D5=B8=D6=80 <strong>=D5=BD.=D5=A9. =D5=B4=D5=A1=D6=80=D5=BF=D5=AB 29-=D5=
=AB=D6=81</strong> =D5=B8=D6=82=D5=AA=D5=AB =D5=B4=D5=A5=D5=BB =D5=A5=D5=B6=
 =D5=B4=D5=BF=D5=B6=D5=A5=D5=AC=D5=B8=D6=82 =D4=B1=D5=AF=D5=A2=D5=A1 =D5=A2=
=D5=A1=D5=B6=D5=AF=D5=AB <strong>=D6=84=D5=A1=D6=80=D5=BF=D5=A1=D5=B5=D5=AB=
=D5=B6 =D5=A3=D5=B8=D6=80=D5=AE=D5=A1=D5=BC=D5=B6=D5=B8=D6=82=D5=A9=D5=B5=
=D5=B8=D6=82=D5=B6=D5=B6=D5=A5=D6=80=D5=AB =D5=BD=D5=A1=D5=AF=D5=A1=D5=A3=
=D5=B6=D5=A5=D6=80=D5=AB</strong>, =D5=AB=D5=B6=D5=B9=D5=BA=D5=A5=D5=BD =D5=
=B6=D5=A1=D6=87 <strong>=D5=A2=D5=A1=D5=B6=D5=AF=D5=AB =D5=BE=D5=B3=D5=A1=
=D6=80=D5=A1=D5=B5=D5=AB=D5=B6 =D6=84=D5=A1=D6=80=D5=BF=D5=A5=D6=80=D5=AB =
=D5=BF=D6=80=D5=A1=D5=B4=D5=A1=D5=A4=D6=80=D5=B4=D5=A1=D5=B6 =D6=87 =D5=BD=
=D5=BA=D5=A1=D5=BD=D5=A1=D6=80=D5=AF=D5=B4=D5=A1=D5=B6 =D5=BA=D5=A1=D5=B5=
=D5=B4=D5=A1=D5=B6=D5=B6=D5=A5=D6=80=D5=AB</strong> =D5=B6=D5=B8=D6=80 =D5=
=AD=D5=B4=D5=A2=D5=A1=D5=A3=D6=80=D5=B8=D6=82=D5=A9=D5=B5=D5=B8=D6=82=D5=B6=
=D5=B6=D5=A5=D6=80=D5=A8:<br /><br />=D5=93=D5=B8=D6=83=D5=B8=D5=AD=D5=B8=
=D6=82=D5=A9=D5=B5=D5=B8=D6=82=D5=B6=D5=B6=D5=A5=D6=80=D5=B6 =D5=A1=D5=BC=
=D5=B6=D5=B9=D5=BE=D5=B8=D6=82=D5=B4 =D5=A5=D5=B6 =D4=B1=D6=80=D5=94=D5=A1 =
=D5=BF=D5=A5=D5=BD=D5=A1=D5=AF=D5=AB =D6=84=D5=A1=D6=80=D5=BF=D5=A5=D6=80=
=D5=AB =D5=BD=D5=A1=D5=AF=D5=A1=D5=A3=D5=B6=D5=A5=D6=80=D5=AB=D5=B6 =D6=87 =
=D5=BA=D5=A1=D5=B5=D5=B4=D5=A1=D5=B6=D5=B6=D5=A5=D6=80=D5=AB=D5=B6=D6=89 <b=
r /><br />=D5=84=D5=A1=D5=BD=D5=B6=D5=A1=D5=BE=D5=B8=D6=80=D5=A1=D5=BA=D5=
=A5=D5=BD, =D5=BD.=D5=A9. =D5=B4=D5=A1=D6=80=D5=BF=D5=AB 29-=D5=AB=D6=81 =
=D5=AF=D5=A1=D5=BD=D5=A5=D6=81=D5=BE=D5=A5=D5=AC=D5=B8=D6=82 =D5=A7 =D4=B1=
=D6=80=D5=94=D5=A1 =D6=84=D5=A1=D6=80=D5=BF=D5=A5=D6=80=D5=B8=D5=BE =D5=BE=
=D5=B3=D5=A1=D6=80=D5=B8=D6=82=D5=B4=D5=B6=D5=A5=D6=80=D5=AB =D5=AB=D6=80=
=D5=A1=D5=AF=D5=A1=D5=B6=D5=A1=D6=81=D5=B4=D5=A1=D5=B6 =D5=B0=D5=B6=D5=A1=
=D6=80=D5=A1=D5=BE=D5=B8=D6=80=D5=B8=D6=82=D5=A9=D5=B5=D5=B8=D6=82=D5=B6=D5=
=A8 =D5=84=D4=BB=D5=90 =D5=BE=D5=B3=D5=A1=D6=80=D5=A1=D5=B5=D5=AB=D5=B6 =D5=
=B0=D5=A1=D5=B4=D5=A1=D5=AF=D5=A1=D6=80=D5=A3=D5=AB =D5=BD=D5=BA=D5=A1=D5=
=BD=D5=A1=D6=80=D5=AF=D5=B4=D5=A1=D5=B6 =D5=A5=D5=B6=D5=A9=D5=A1=D5=AF=D5=
=A1=D5=BC=D5=B8=D6=82=D6=81=D5=BE=D5=A1=D5=AE=D6=84=D5=B8=D6=82=D5=B4, =D5=
=AB=D5=B6=D5=B9=D5=A8 =D5=B6=D5=B7=D5=A1=D5=B6=D5=A1=D5=AF=D5=B8=D6=82=D5=
=B4 =D5=A7, =D5=B8=D6=80</p>
<ul>
<li>=D4=B1=D5=AF=D5=A2=D5=A1 =D5=A2=D5=A1=D5=B6=D5=AF=D5=AB =D4=B1=D6=80=D5=
=94=D5=A1 =D5=B9=D5=AB=D5=BA=D5=A1=D5=B5=D5=AB=D5=B6, =D5=A1=D5=B5=D5=A4 =
=D5=A9=D5=BE=D5=B8=D6=82=D5=B4=D5=9D =D4=B1=D6=80=D5=94=D5=A1 =D5=84=D4=BB=
=D5=90 =D6=84=D5=A1=D6=80=D5=BF=D5=A5=D6=80=D5=B8=D5=BE =D5=B0=D5=B6=D5=A1=
=D6=80=D5=A1=D5=BE=D5=B8=D6=80 =D5=B9=D5=AB =D5=AC=D5=AB=D5=B6=D5=A5=D5=AC=
=D5=B8=D6=82 =D5=AB=D6=80=D5=A1=D5=AF=D5=A1=D5=B6=D5=A1=D6=81=D5=B6=D5=A5=
=D5=AC =D5=AF=D5=A1=D5=B6=D5=AD=D5=AB=D5=AF=D5=A1=D6=81=D5=B4=D5=A1=D5=B6 =
=D6=87/=D5=AF=D5=A1=D5=B4 =D5=BE=D5=B3=D5=A1=D6=80=D5=A1=D5=B5=D5=AB=D5=B6 =
=D5=A3=D5=B8=D6=80=D5=AE=D5=A1=D6=80=D6=84=D5=B6=D5=A5=D6=80 =D5=8C=D4=B4-=
=D5=B8=D6=82=D5=B4,</li>
<li>=D4=B1=D5=AF=D5=A2=D5=A1 =D5=A2=D5=A1=D5=B6=D5=AF=D5=AB =D4=B1=D6=80=D5=
=94=D5=A1 =D6=84=D5=A1=D6=80=D5=BF=D5=A5=D6=80=D5=AB=D5=B6 =D5=AF=D5=BD=D5=
=A1=D5=B0=D5=B4=D5=A1=D5=B6=D5=A1=D6=83=D5=A1=D5=AF=D5=BE=D5=AB =D5=84=D4=
=BB=D5=90 =D5=BE=D5=B3=D5=A1=D6=80=D5=A1=D5=B5=D5=AB=D5=B6 =D5=B0=D5=A1=D5=
=B4=D5=A1=D5=AF=D5=A1=D6=80=D5=A3=D5=AB=D6=81 =D5=BD=D5=BF=D5=A1=D6=81=D5=
=BE=D5=B8=D5=B2 =D6=84=D5=A1=D6=80=D5=BF=D5=AB=D6=81 =D6=84=D5=A1=D6=80=D5=
=BF =D6=83=D5=B8=D5=AD=D5=A1=D5=B6=D6=81=D5=B8=D6=82=D5=B4=D5=B6=D5=A5=D6=
=80=D5=A8=D6=89</li>
</ul>
<p style=3D"text-align: left;"><strong>=D5=88=D6=82=D5=B7=D5=A1=D5=A4=D6=80=
=D5=B8=D6=82=D5=A9=D5=B5=D5=B8=D6=82=D5=B6:</strong> =D4=B2=D5=A1=D5=B6=D5=
=AF=D5=AB =D5=AF=D5=B8=D5=B2=D5=B4=D5=AB=D6=81 =D5=A9=D5=B8=D5=B2=D5=A1=D6=
=80=D5=AF=D5=BE=D5=A1=D5=AE =D4=B1=D6=80=D5=94=D5=A1 =D5=A2=D5=B8=D5=AC=D5=
=B8=D6=80 =D5=BF=D5=A5=D5=BD=D5=A1=D5=AF=D5=AB =D6=84=D5=A1=D6=80=D5=BF=D5=
=A5=D6=80=D5=A8=D5=9D =D5=A1=D5=B5=D5=A4 =D5=A9=D5=BE=D5=B8=D6=82=D5=B4 =D5=
=B6=D5=A1=D6=87 =D4=B1=D6=80=D5=94=D5=A1 =D5=84=D4=BB=D5=90 =D6=84=D5=A1=D6=
=80=D5=BF=D5=A5=D6=80=D5=A8, =D5=AF=D5=B7=D5=A1=D6=80=D5=B8=D6=82=D5=B6=D5=
=A1=D5=AF=D5=A5=D5=B6 =D5=A1=D5=BC=D5=A1=D5=B6=D6=81 =D5=AD=D5=B8=D5=B9=D5=
=A8=D5=B6=D5=A4=D5=B8=D5=BF=D5=AB =D5=BD=D5=BA=D5=A1=D5=BD=D5=A1=D6=80=D5=
=AF=D5=BE=D5=A5=D5=AC =D5=80=D5=80-=D5=B8=D6=82=D5=B4=D5=9D =D4=B1=D6=80=D5=
=94=D5=A1 =D5=BE=D5=B3=D5=A1=D6=80=D5=A1=D5=B5=D5=AB=D5=B6 =D5=B0=D5=A1=D5=
=B4=D5=A1=D5=AF=D5=A1=D6=80=D5=A3=D5=AB =D5=BD=D5=BA=D5=A1=D5=BD=D5=A1=D6=
=80=D5=AF=D5=B4=D5=A1=D5=B6 =D5=A5=D5=B6=D5=A9=D5=A1=D5=AF=D5=A1=D5=BC=D5=
=B8=D6=82=D6=81=D5=BE=D5=A1=D5=AE=D6=84=D5=B8=D6=82=D5=B4=D6=89<br /><br />=
=D5=93=D5=B8=D6=83=D5=B8=D5=AD=D5=BE=D5=A1=D5=AE =D5=BD=D5=A1=D5=AF=D5=A1=
=D5=A3=D5=B6=D5=A5=D6=80=D5=AB=D5=B6 =D5=A1=D5=BC=D5=A1=D5=BE=D5=A5=D5=AC =
=D5=B4=D5=A1=D5=B6=D6=80=D5=A1=D5=B4=D5=A1=D5=BD=D5=B6 =D5=AF=D5=A1=D6=80=
=D5=B8=D5=B2 =D5=A5=D6=84 =D5=AE=D5=A1=D5=B6=D5=B8=D5=A9=D5=A1=D5=B6=D5=A1=
=D5=AC <span style=3D"color: #00a688;"><strong><a rel=3D"noopener noreferre=
r" href=3D"https://email.mg.acba.am/c/eJxEjs_rnDAQR_-a8aYkk1968GBNpZdCael5G=
aPZDTUqibLsf18Wdvd7e3zeY5ip5V5zPxZzyw3nUtfaYHFrqfENOU6MnK-1lLVRhMaZWY6K89oV=
oUWGkgnUXCmjsJLTSEZP3kgUzHgOksVrRW6kimKxtLfj2DOIDnAAHO73-9sBDj4scwYcHKUplwe=
l4H0usamYqPbJgxgy7eV2HuN2rlMZJhDWdkI0vcX-u5W96WsrrW10ZzuBkvWqfwrWMw2ozyNe8n=
YmN4Owf7pfPx5jCvkl4jyFM4Kwc6SwvEZHcadwXUFYo_A1HnN6dj_LGFJJy1JScnS5XACVVYCq4=
2_6pj5kPzR8ui_7Pu229ZjXA4T9_bdI7Y0e_2g9841yetDKGEh2fb5XuS3-DwAA__-UI39z" ta=
rget=3D"_blank" title=3D"=D5=A1=D5=B5=D5=BD=D5=BF=D5=A5=D5=B2" style=3D"col=
or: #00a688;">=D5=A1=D5=B5=D5=BD=D5=BF=D5=A5=D5=B2</a></strong></span>, =D5=
=AB=D5=BD=D5=AF =D6=84=D5=A1=D6=80=D5=BF=D5=A5=D6=80=D5=AB =D5=B6=D5=B8=D6=
=80 =D5=BA=D5=A1=D5=B5=D5=B4=D5=A1=D5=B6=D5=B6=D5=A5=D6=80=D5=AB=D5=B6=D5=
=9D =D5=B0=D5=A5=D5=BF=D6=87=D5=B5=D5=A1=D5=AC <strong><span style=3D"color=
: #00a68a;"><a rel=3D"noopener noreferrer" href=3D"https://email.mg.acba.am=
/c/eJxsjsvK2zAQRp9mvLORRjdn4YVr1XRTKC1dh7EuiallB0sm5O1LIMnq3x3OGYbPdzxqHqcq=
dNxwLnWrDVbXTkXkIijdBtVGGZXycnKTQDTOsdbLau6QoWQCNVfKKGykn8hoH41EwUzkIFm6NOQ=
maihVS3ct5ZZB9IAj4Hi_398NcIzzEjLg6Gj3uS6A2tV4aphobj6CGDPd6u0o03asvp49CGt7IU=
6DxeG7lYMZWiutPene9gIlG9TwDGxgGlAfJZ3zduwugLB_-l8_HtM-51dIwc9HAmFDonl5SUfpR=
vNlBWGNwpcsYX_e_azTvNe0LDXtjs7nM6CyClB9Yx_CD8k39fwL937ttrWEtYCwv_9We3elxz9a=
j3ylvD9oZQwkuzznNW5L_wMAAP__MMF9kg" target=3D"_blank" title=3D"=D5=B0=D5=B2=
=D5=B4=D5=A1=D5=B4=D5=A2" style=3D"color: #00a68a;">=D5=B0=D5=B2=D5=B4=D5=
=A1=D5=B4=D5=A2</a></span></strong>=D6=89<br /><br />=D5=8E=D5=A5=D6=80=D5=
=B8=D5=B6=D5=B7=D5=B5=D5=A1=D5=AC =D6=87 =D5=A1=D5=B5=D5=AC =D5=A2=D5=B8=D5=
=AC=D5=B8=D6=80 =D6=83=D5=B8=D6=83=D5=B8=D5=AD=D5=B8=D6=82=D5=A9=D5=B5=D5=
=B8=D6=82=D5=B6=D5=B6=D5=A5=D6=80=D5=A8 =D5=B6=D5=B7=D5=BE=D5=A1=D5=AE =D5=
=A5=D5=B6 =D5=AF=D5=A1=D5=BA=D5=B8=D6=82=D5=B5=D5=BF =D5=A3=D5=B8=D6=82=D5=
=B5=D5=B6=D5=B8=D5=BE:<br /><br /></p>
</div>
<div style=3D"padding: 0 7%;">
<div class=3D"media_link" style=3D"padding-bottom: 15px; max-height: 22px; =
text-align: center;"><a rel=3D"noopener noreferrer" href=3D"https://email.m=
g.acba.am/c/eJw0j02LpDAQQH9NvCmVVEy6Dx7ErOxlYZlhzlL5sHXamEYjTf_7Qei5vveKqvI=
NHxUfbREarjmX6qK0KKYGBHiCK1AgabX3XEItfbjwQIiOVDE3AoQEFIrXta5FJb0lrfyopUDQI2=
cS4q0iZ6miWCzNlPNjZ9gy0TPRP5_PaiQXbEr3yqXIRH-mltZ7lb53x7Df6VGmI9t0rL6cPUNjW=
sRrZ0T3x8hOdxcjjbmq1rQoJHR1dwroQDGhjhyHPR2bCwzNZ_v_78tu8_4WMfj5iAxNiDQvb-go=
Pmi-rQyNrsUb5rCd3b8yzltJy1LS5mgYhvPWcrS_o2nNYc0MzcdXsTUTve60HvtE-_aiFYBJuJ2=
bzkd_AgAA__8bd3Jw" target=3D"_blank" title=3D"acba-fb" style=3D"text-decora=
tion: none;"> <img src=3D"https://acba.blob.core.windows.net/uploads/facebo=
ok.jpg" alt=3D"acba-fb" title=3D"acba-fb" style=3D"max-height: 22px; opacit=
y: 1;" /> </a> <a rel=3D"noopener noreferrer" href=3D"https://email.mg.acba=
.am/c/eJw0kE_vnCAQhj8N3jAICMvBg5GaXpo0bXreDH9UsoIGMRu_fWO7v-v7zJOZeV3XTKKZT=
OW7RjYNFw8habV0XrZeKceVU4bKhzBeeSUe3sOkGHCoQkcJ5YRR0bStbGnNnQEp3CQ5ZURODeIk=
zjVYAzXEau2WUvYDsR7REdHx_X7Xa0gv70Kq7RYRHe0Wd0gXouMtYZu9CwXDnIPdVo8NpBdi4wE=
73s5itjM5HBxiWveMqUHT4ZvmgxwemmutRK97RjkZ2uEGZCACUXGW-Dy2M1uPmP7d__x-mRyOD4=
jehTMipn2EsH5CC3GHMCfEtGzpJyw-33M_cAwZw7piyBaez-e_u_9_9aVvqfhUENO__lS5W-B6Q=
TqPBY58QSIEcTLf2-4K_gYAAP__euJ8fg" target=3D"_blank" title=3D"acba-linked" =
style=3D"text-decoration: none;"> <img src=3D"https://acba.blob.core.window=
s.net/uploads/linkedin.jpg" alt=3D"acba-linked" title=3D"acba-linked" style=
=3D"max-height: 22px; opacity: 1;" /> </a> <a rel=3D"noopener noreferrer" h=
ref=3D"https://email.mg.acba.am/c/eJw0j82KpTAQhZ8m7pT8mejChZiR2QwM3fRaKjHR0=
EYvMeHi2zeCvT2nPup8c0ecIE4XtiOSEC4aIWmxdrXTzEoNzklNnNFWc9kK3LRgoW6kLXxHMeWY=
UUHqWta04rMGKWYnOWVYOoI4DksFRkMFodi6NaXXiViP6Ijo-H6_q-vIKWtbmSMgOubTRkTHGzD=
Rzj7BEr05NovYeMKrPHLSR97n0s-IKdUz1g6KDn8UH-TQKK5UK3rVM8rxUA93gQcsEBU5hek8cj=
QWMfXZ__976ejPpwh29jkgpmwAvz2hgfACv-yIKVnTJ0w23nf_yuBjCdtWQjQwTdM9uHxUfvljT=
3ZPiKmPryJ2K1zfsOdzhTNesGOMOF7ud7f5TwAAAP__ZDR57A" target=3D"_blank" title=
=3D"acba-youtube" style=3D"text-decoration: none;"> <img src=3D"https://acb=
a.blob.core.windows.net/uploads/youtube.jpg" alt=3D"acba-youtube" title=3D"=
acba-youtube" style=3D"max-height: 22px; opacity: 1;" /> </a> <a rel=3D"noo=
pener noreferrer" href=3D"https://email.mg.acba.am/c/eJw8j81qhDAUhZ8m7pT8Z2=
bhQkylm0Jp6VpuTNQwJg5JZJi3L8K023M-7v2ObcksyWwq1xJFCJcXqWi1tjMYRoW9SKGwAuEUC=
EWcm-CqiCTGVr6lmHLMqCRCKEEbbg0oaWfFKcNqJojjsDQwGWggVFu7lnLPiHWIDogOj8ej8TEX=
WBKEZtoDosPJGog3xIYM93o_itmPaGtvEdO6Y-zaa9q_ad6r_qK51lfZ6Y5RjnvRnwXusURUHiW=
MeT_S5BDT393n-9Mkn19FcNYfATHtAvjtFU4Q7uCXiJhWgr7C4tLJfdTBpxq2rYY0wTiOp2b97_=
53YY_FxYKY_vqpUrvC8wbxyCvk9ISIMeJ4OR-eU38DAAD__4N4dA8" target=3D"_blank" ti=
tle=3D"acba-instagram" style=3D"text-decoration: none;"> <img src=3D"https:=
//acba.blob.core.windows.net/uploads/instagram.jpg" alt=3D"acba-instagram" =
title=3D"acba-instagram" style=3D"max-height: 22px; opacity: 1;" /></a></di=
v>
</div>
</div>
<div class=3D"footer_holder" style=3D"background-color: #5f5e61;">
<div class=3D"footer" style=3D"margin: 0 auto; width: 85%; color: #ececec; =
font-size: 12px; padding: 10px 0;">
<p style=3D"margin: 0px auto; text-align: center;"><span style=3D"font-size=
: 8pt;">=E2=92=B8 2024 &laquo;=D4=B1=D4=BF=D4=B2=D4=B1 =D4=B2=D4=B1=D5=86=
=D4=BF&raquo; =D4=B2=D4=B2=D4=B8</span><br /><span style=3D"font-size: 8pt;=
"><a href=3D"https://email.mg.acba.am/c/eJw0kMtu4kAQRb_GLFF19dMLFsbtZoYBJyZ=
gA5uoHzgm2AQFSMZ8_Yig2ZXq1C3pnjAitSC1G-xGRBLChBISB81oh44HSWIvlGWqFpZ6VUuFjv=
Jgd_VusB8hIAOKgnAuOQ5ZcFaKUEuGFGRNIgbd29B6Z4e2G7Sj5nI5nSOaRGgiNGd7sqcTAcCfE=
2-H7Ye3bUQTxuiDR2hOV9fufYTGX-0xQtPuj4cIDQCJ0OiE0jjVmGaapTJVmmkdi0QnFBmkPL0D=
SEFE1LyWrxHVGKF4_UPIfR4LIzUywThwmaSJ1KkWWWaIwNSkWhGdAbKM3iMzzhJNDAK7Jz3mret=
MbysVL1d_9SrzXZiYfoslPFcNhF_j29NefQUa6Kwz75suu24quJdA8z2rYhIm069Q8cOsag_Pq8=
V4fpvzAoq-gDLLszktbk2WZ4vsabkdL7LsNn8vvotbqeeH3Cz0WM_1pgvrxWVN86-wnr5vl2RZl=
OPfu2ra2_X8wZC020lL3JK0rjInl25JmJB6g-biJ-a0RRbnt1U_PZbgyhi26-nleQUXV7X9rDJn=
l5LGd3mzJnG9qfL95oU37uX_j_gaJuU1aPJSFg-p9K5GSKUAHosfV0pJaqWXNFDiaq94UNYLLpV=
UiIpzdHQnKZUxWEZDzBjEFIWIJWHMxVIMPkeN7Q_2eD039vzZ2yNAxOCts_t26D-6fwEAAP__ZA=
3Lsg" title=3D"acba.am" style=3D"color: #ececec; font-weight: bold; text-de=
coration: none;">acba.am</a> | 010 31 88 88 | =D4=B2=D5=A1=D5=B6=D5=AF=D5=
=A8 =D5=BE=D5=A5=D6=80=D5=A1=D5=B0=D5=BD=D5=AF=D5=BE=D5=B8=D6=82=D5=B4 =D5=
=A7 =D5=80=D5=80 =D4=BF=D4=B2 =D5=AF=D5=B8=D5=B2=D5=B4=D5=AB=D6=81=D6=89</s=
pan><br /><span style=3D"font-size: 8pt;">=D4=BD=D5=B6=D5=A4=D6=80=D5=B8=D6=
=82=D5=B4 =D5=A5=D5=B6=D6=84 =D5=BD=D5=A5=D5=B2=D5=B4=D5=A5=D5=AC <a href=
=3D"mailto:callcenter@acba.am?subject=3D%D5%80%D6%80%D5%A1%D5%AA%D5%A1%D6%8=
0%D5%BE%D5%A5%D5%AC%20%D5%A3%D6%80%D5%A1%D5%B6%D6%81%D5%B8%D6%82%D5%B4%D5%A=
B%D6%81&body=3D%D5%80%D6%80%D5%A1%D5%AA%D5%A1%D6%80%D5%BE%D5%B8%D6%82%D5%B4=
%20%D5%A5%D5%B4%20%D5%BD%D5%BF%D5%A1%D5%B6%D5%A1%D5%AC%20%D5%B6%D5%B4%D5%A1=
%D5%B6%D5%A1%D5%BF%D5%AB%D5%BA%20%D5%AE%D5%A1%D5%B6%D5%B8%D6%82%D6%81%D5%B8=
%D6%82%D5%B4%D5%B6%D5%A5%D6%80%20%D5%AB%D5%B4%20%D5%A7%D5%AC%D5%A5%D5%AF%D5=
%BF%D6%80%D5%B8%D5%B6%D5%A1%D5%B5%D5%AB%D5%B6%20%D5%B0%D5%A1%D5%BD%D6%81%D5=
%A5%D5%AB%D5%B6%D6%89" title=3D"=D5=A1=D5=B5=D5=BD=D5=BF=D5=A5=D5=B2" style=
=3D"color: #ececec; font-weight: bold; text-decoration: none;"> =D5=A1=D5=
=B5=D5=BD=D5=BF=D5=A5=D5=B2 </a> =D5=AF=D5=A1=D5=B4 =D5=A6=D5=A1=D5=B6=D5=
=A3=D5=A1=D5=B0=D5=A1=D6=80=D5=A5=D5=AC <a href=3D"tel:+37410-31-88-88" tit=
le=3D"phone" style=3D"color: #ececec; font-weight: bold; text-decoration: n=
one;"> +374 10 31 88 88 </a> =D5=B0=D5=A5=D5=BC=D5=A1=D5=AD=D5=B8=D5=BD=D5=
=A1=D5=B0=D5=A1=D5=B4=D5=A1=D6=80=D5=AB=D5=B6, =D5=A5=D5=A9=D5=A5 =D5=B9=D5=
=A5=D6=84 =D6=81=D5=A1=D5=B6=D5=AF=D5=A1=D5=B6=D5=B8=D6=82=D5=B4 =D5=BD=D5=
=BF=D5=A1=D5=B6=D5=A1=D5=AC =D5=B6=D5=B4=D5=A1=D5=B6=D5=A1=D5=BF=D5=AB=D5=
=BA =D5=B6=D5=A1=D5=B4=D5=A1=D5=AF=D5=B6=D5=A5=D6=80:</span></p>
</div>
</div>
</div></div><!--[if mso]></td></tr></table><![endif]--><!-- body-content-pl=
aceholder --><img width=3D"1px" height=3D"1px" alt=3D"" src=3D"https://emai=
l.mg.acba.am/o/eJwEwEGuhCAMANDTyJK0tbS44DDFgpj_cRLNLLz9PC_YBXsNraAismRRCqMI=
gTavKFnZ6tYAqG2WW66-YnIJZyEghpUEU9JEkb2aindlWkE7LgzziLZXizbDXYa9f3Z9n2HP_do=
FsDAc087_uH_mLwAA__-DyyaN"></body></html>'''

emailDomain = "mg.acba.am"

analysis = emailSpoofDetection(header, emailDomain)

print(analysis)

# {'validEmail': True}
# {'validEmail': False}
