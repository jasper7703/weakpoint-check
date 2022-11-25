#!/bin/bash
#tes commit
#################################################################################
#                                                                               #
#   Program Name : Security Check for LINUX for Ubuntu                          #
#   Version : V1.00                                                             #
#   Description : 이 스크립트는 LINUX 서버 시스템 보안패치 스크립트 입니다.     #
#   Author : 이승준 연구원 / (주)Altimobility                                   #
#                                                                               #
#-------------------------------------------------------------------------------#
#                                                                               #
# 본 스크립트의 문제점을 발견시 반드시 sj.lee2@alti-mobility.com 연락  바랍니다.#
#                                                                               #
# 반드시 실행 할때는 root 권한으로 실행하여 주시길 바랍니다.			#
#                                                                               #
#################################################################################
if [ -f /root/count1.txt ]
then
 echo "이미 보안조치 스크립트를 실행 했습니다."
 exit 1

else 
echo "취약점 조치를 시작합니다."
echo "U-01) 원격 접속시 ROOT계정으로 접속 할 수 없도록 설정 (serviec sshd restart 필요)"

sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin no/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config # 2022-11-21 added

cat /etc/ssh/sshd_config | grep PermitRootLogin

echo "securetty 파일 복사 /etc/securetty" # 2022-11-21 added
cp /usr/share/doc/util-linux/examples/securetty /etc
echo "pts/0" >> /etc/securetty
echo "pts/1" >> /etc/securetty
echo "pts/2" >> /etc/securetty
echo "pts/3" >> /etc/securetty
echo "pts/4" >> /etc/securetty

#pam_securetty.so 수정하는중


echo "U-02) 패스워드 복잡성 설정 cat / /etc/security/pwquality.conf 확인" 
#sed -i 's/# dcredit = 1/dcredit = -1/g' /etc/security/pwquality.conf
#sed -i 's/# ucredit = 1/ucredit = -1/g' /etc/security/pwquality.conf
#sed -i 's/# ocredit = 1/ocredit = -1/g' /etc/security/pwquality.conf
#sed -i 's/# lcredit = 1/lcredit = -1/g' /etc/security/pwquality.conf
if [ -f /etc/security/pwquality.conf ]
  then
  	sed -i 's/^.*minlen.*/minlen = 8/g' /etc/security/pwquality.conf
	sed -i 's/^.*dcredit.*/dcredit = -1/g' /etc/security/pwquality.conf
	sed -i 's/^.*ucredit.*/ucredit = -1/g' /etc/security/pwquality.conf
	sed -i 's/^.*lcredit.*/lcredit = -1/g' /etc/security/pwquality.conf
	sed -i 's/^.*ocredit.*/ocredit = -1/g' /etc/security/pwquality.conf
	if [ `cat /etc/security/pwquality.conf | grep -E "minlen" | wc -l` -lt 1 ]
    then
    	echo "minlen = 8" >> /etc/security/pwquality.conf
	fi
	if [ `cat /etc/security/pwquality.conf | grep -E "dcredit" | wc -l` -lt 1 ]
    then
		echo "dcredit = -1" >> /etc/security/pwquality.conf
	fi
	if [ `cat /etc/security/pwquality.conf | grep -E "ucredit" | wc -l` -lt 1 ]
    then
		echo "ucredit = -1" >> /etc/security/pwquality.conf
	fi
	if [ `cat /etc/security/pwquality.conf | grep -E "lcredit" | wc -l` -lt 1 ]
    then
		echo "lcredit = -1" >> /etc/security/pwquality.conf
	fi
	if [ `cat /etc/security/pwquality.conf | grep -E "ocredit" | wc -l` -lt 1 ]
    then
		echo "ocredit = -1" >> /etc/security/pwquality.conf
	fi
fi
sed -n '11,25p' /etc/security/pwquality.conf

echo "U-03) 계정잠금 임계값 설정 cat /etc/pam.d/password-auth-ac system-auth-ac 수정"
#perl -p -i -e '$.==9 and print "auth required pam_tally2.so deny=5 unlock_time=120\n"' /etc/pam.d/password-auth-ac
#perl -p -i -e '$.==16 and print "account required pam_tally2.so\n"' /etc/pam.d/password-auth-ac
#perl -p -i -e '$.==9 and print "auth required pam_tally2.so deny=5 unlock_time=120\n"' /etc/pam.d/system-auth-ac
#perl -p -i -e '$.==16 and print "account required pam_tally2.so\n"' /etc/pam.d/system-auth-ac
if [ -f /etc/pam.d/system-auth ]
	then
	if [ `cat /etc/*-release | uniq | grep -E 'release 5|release 6' | wc -l` -gt 0 ]
		then
		echo "CentOS 5 또는 6 버젼 쉘 실행"
		 sed -i 's/auth.*required.*\/lib\/security\/pam_tally.so.*/auth 	required 	\/lib\/security\/pam_tally.so deny=5 unlock_time=120 no_magic_root/g' /etc/pam.d/system-auth
		 sed -i 's/account.*required.*\/lib\/security\/pam_tally.so.*/account 	required 	\/lib\/security\/pam_tally.so no_magic_root reset/g' /etc/pam.d/system-auth
		if [ `cat /etc/pam.d/system-auth | grep -E "pam_tally" | wc -l` -lt 1 ]
		  then
		   echo "auth		required 	/lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root" >> /etc/pam.d/system-auth
		   echo "account 	required 	/lib/security/pam_tally.so no_magic_root reset" >> /etc/pam.d/system-auth
		fi 
	else
		echo "CentOS 7 이상 버젼 쉘 실행"
		 sed -i 's/auth.*required.*pam_tally2.so.*/auth 	required 	pam_tally2.so deny=5 unlock_time=120 no_magic_root/g' /etc/pam.d/system-auth
		 sed -i 's/account.*required.*pam_tally2.so.*/account 	required 	pam_tally2.so no_magic_root reset/g' /etc/pam.d/system-auth
		if [ `cat /etc/pam.d/system-auth | grep -E "pam_tally" | wc -l` -lt 1 ]
		  then
		   echo "auth 	required 	pam_tally2.so deny=5 unlock_time=120 no_magic_root" >> /etc/pam.d/system-auth
		   echo "account 	required 	pam_tally2.so no_magic_root reset" >> /etc/pam.d/system-auth
		fi 
	fi
fi
if [ -f /etc/pam.d/password-auth ]
  then
        sed -i 's/auth.*required.*pam_tally2.so.*/auth 	required 	pam_tally2.so deny=5 unlock_time=120 no_magic_root/g' /etc/pam.d/password-auth
		sed -i 's/account.*required.*pam_tally2.so.*/account 	required 	pam_tally2.so no_magic_root reset/g' /etc/pam.d/password-auth
	    if [ `cat /etc/pam.d/password-auth | grep -E "pam_tally" | wc -l` -lt 1 ]
		  then
  		 echo "auth 	required 	pam_tally2.so deny=5 unlock_time=120 no_magic_root" >> /etc/pam.d/password-auth
		 echo "account 	required 	pam_tally2.so no_magic_root reset" >> /etc/pam.d/password-auth
		fi
fi
cat /etc/pam.d/password-auth-ac | grep pam_tally2.so
cat /etc/pam.d/system-auth-ac | grep pam_tally2.so

echo "U-04) 패스워드 파일 보호 cat /etc/shadow"
pwconv
echo "U-44) root이외 UID '0' 금지 /etc/passwd"
USRDET=`cat /etc/passwd | grep -E ":x:0:" | grep -v "^root:"`
UIDSET=`cat /etc/passwd | cut -d: -f3`
MAXNUM=0
for TT in $UIDSET
do
  if [ $TT -gt $MAXNUM ]
   then
   MAXNUM=$TT
  fi
done
MAXNUM=$((MAXNUM+1))
for USDT in $USRDET
do
 TOKDT=`cut -d: -f1 <<< $USDT`
 sed -i "s/^$TOKDT:x:0:/$TOKDT:x:$MAXNUM:/" /etc/passwd
 MAXNUM=$((MAXNUM+1))
done
unset USRDET
unset SET
unset MAXNUM
unset TT
unset USDT
unset TOKDT

echo "U-45) wheel 그룹내 구성원 존재 여부 확인 cat /etc/group | grep wheel"
sed -i 's/wheel:x:10:/wheel:x:10:root,alticast,admin/g' /etc/group
echo "U-45) root 계정 su 제한조치"
sed -i '/s#auth            required        pam_wheel.so use_uid/auth            required        pam_wheel.so use_uid/g' /etc/pam.d/su
chgrp wheel /bin/su
chmod 4755 /bin/su
cat /etc/group | grep wheel
ls -al /bin/su
echo "U-45) 조치 후 nutanix를 포함한 가상 서버(클라우드포함) 시스템은 상태 확인 필요. 로컬서버의 경우 적용확인."

echo "U-46) 패스워드 최소길이 설정 cat /etc/login.defs"
echo "U-47) 패스워드 최대 사용기간 설정 60일"
echo "U-48) 패스워드 최소 사용기간 1일"
sed -i 's/PASS_MAX_DAYS	99999/PASS_MAX_DAYS 60/g' /etc/login.defs
sed -i 's/PASS_MIN_DAYS	0/PASS_MIN_DAYS 1/g' /etc/login.defs
sed -i 's/PASS_MIN_LEN	5/PASS_MIN_LEN 8/g' /etc/login.defs
sed -i 's/PASS_WARN_AGE	7/PASS_WARN_AGE 7/g' /etc/login.defs
sed -n '25,28p' /etc/login.defs

echo "U-49) 불필요한 계정 제거(기존 로그인계정은 처리되어있으며 나머지 모두 nologin 처리"
echo "user adm,lp,news,games,gopher group adm, lp, news 삭제처리"
userdel adm
userdel lp
userdel news
userdel games
userdel gopher
groupdel adm
groupdel lp
groupdel news
groupdel games

echo "U-50) 관리자 그룹에 최소한의 계정포함(root,alticast,admin 기본 등록처리 cat /etc/group | grep root"
echo "U-51) 계정이 존재하지 않는 GID 금지 (기존 조치됨 cat /etc/group)"
echo "U-52) 동일한 UID 금지 cat /etc/passwd (기존 조치됨)"
UIDSET=`cat /etc/passwd | sort -k 3 -n -t: | cut -d: -f3`
MAXNUM=`echo $UIDSET | rev | cut -d" " -f1 | rev`
MAXNUM=$((MAXNUM+1))
COMP=-1
for TT in $UIDSET
do
  if [ $TT -eq $COMP ]
   then
    USRID=`cat /etc/passwd | grep -E ":x:$TT:" | cut -d: -f1 | tail -1`
    sed -i "s/^$USRID:x:$TT/$USRID:x:$MAXNUM/" /etc/passwd
	MAXNUM=$((MAXNUM+1))
  fi
  COMP=$TT
done
unset UIDSET
unset MAXNUM
unset COMP
unset TT
unset USRID

echo "U-53) 사용자 shell 점검(일반적사용 X) 로그인이 필요하지 않는 계정에 대해 /sbin/nologin 부여 (기존조치됨 /etc/passwd)"
echo "U-54) 세션 타입 아웃 설정 600초 설정완료"
if [ -f /etc/profile ]
  then
	sed -i 's/^TMOUT.*/TMOUT=600/g' /etc/profile
	if [ `cat /etc/profile | grep -E "TMOUT" | wc -l` -lt 1 ]
	then
		echo "TMOUT=600" >> /etc/profile
		echo "export TMOUT" >> /etc/profile
	fi
fi
if [ -f /etc/.profile ]
  then
  	sed -i 's/^TMOUT.*/TMOUT=600/g' /etc/.profile
	if [ `cat /etc/.profile | grep -E "TMOUT" | wc -l` -lt 1 ]
	then
		echo "TMOUT=600" >> /etc/.profile
		echo "export TMOUT" >> /etc/.profile
	fi
fi
if [ -f /etc/csh.login ]
  then
    sed -i 's/^set autologout.*/set autologout=10/g' /etc/csh.login
	if [ `cat /etc/csh.login | grep -E "autologout" | wc -l` -lt 1 ]
	then
		echo "set autologout=10" >> /etc/csh.login
	fi
fi
#sed -i 's/# will prevent the need for merging in future updates./export TMOUT=300/g'  /etc/profile
cat /etc/profile | grep TMOUT

echo "U-05) root홈, 패스 디렉터리 권한 및 패스 설정 (echo $PATH)"
echo "$PATH"
echo "U-06) 파일 및 디렉터리 소유자 설정 (cat /.bash_profile .bashrc | grep PATH)"
cat /.bash_profile .bashrc | grep PATH
echo "U-07) /etc/passwd 파일 소유자 및 권한 설정 ls -al /etc/passwd"
chown root:root /etc/passwd
chmod 644 /etc/passwd
ls -al /etc/passwd

echo "U-08) /etc/shadow 파일 소유자 및 권한 설정 ls -al /etc/shadow"
chown root:root /etc/shadow
chmod 000 /etc/shadow
ls -al /etc/shadow

echo "U-09) /etc/hosts 파일 소유자 및 권한 설정"
chmod 640 /etc/hosts.allow
chmod 640 /etc/hosts.deny
ls -al /etc/hosts.*

echo "U-10) /etc/(x)inetd.conf 파일 소유자 및 권한 설정 (서비스가 없어 해당없음)"
echo "U-11) /etc/syslog.conf 파일 소유자 및 권한 설정 ls -al /etc/rsyslog.conf"
chown root:root /etc/rsyslog.conf
chmod 644 /etc/rsyslog.conf
ls -al /etc/rsyslog.conf

echo "U-12) /etc/services 파일 소유자 및 권한 설정 la -al /etc/services"
chown root:root /etc/services
chmod 644 /etc/services
ls -al /etc/services

echo "U-13) SUID, SGID, Sticky bit 설정 및 권한 설정"
chmod -s /sbin/unix_chkpwd
chmod -s /usr/bin/at
chmod -s /usr/bin/lpq
chmod -s /usr/bin/lpr
chmod -s /usr/bin/lprm
chmod -s /usr/bin/newgrp
chmod -s /usr/sbin/lpc
chmod -s /usr/bin/traceroute

echo "U-14) 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정(bashrc bash_profile 설정완료)"
chown root:root /etc/profile
chown root:root /etc/bashrc
chown root:root /root/.bashrc
chown root:root /root/.bash_profile
chmod 644 /etc/profile
chmod 644 /etc/bashrc
chmod 644 /root/.bashrc
chmod 644 /root/.bash_profile

echo "U-15) world writable 파일 점검 (조치되어있음.점검시 표기되는 부분은 dev부분으로 조치불가.아래명령으로확인)"
echo "find / -perm -2 -type d -exec ls -aldL {} \;"

echo "U-16) dev에 존재하지 않는 device 파일 점검(아래명령 수동 확인 필요), 관련부분 조치 불가"
echo "find /dev -type f -exec ls -l {} \;"

echo "U-17) $HOME/.rhosts, hosts.equiv 사용 금지 (이미 조치되어있음 파일 없음)"
echo "U-18) 접속 IP 및 포트 제한 (/etc/hosts.allow hosts.deny 파일 수동 조치 필요,환경에 따라 조치)"
echo "U-55) hosts.lpd 파일 소유자 및 권한 설정 (해당없음 파일 없음)"
echo "U-56) NIS 서비스 비활성화 (서비스 없음)"
echo "U-57) UMASK 설정 관리 umask"
if [ `umask` -ne 0022 ]
 then
  sed -i 's/umask [^a-z]../umask 002/' /etc/profile
  sed -i 's/umask [^a-z]../umask 022/' /etc/profile
fi
source /etc/profile

echo "U-58) 홈디렉터리 소유자 및 권한 설정 확인 필요"
echo "U-59) 홈디렉터리로 지정한 디렉토리의 존재 관리 (사용자 계정과 홈 디렉터리의 일치 여부를 점검. 수동 확인 필요)"
echo "U-60) 숨겨진 파일 및 디렉토리 점검 및 제거 (수동확인필요) find / -name '.*'"
echo "U-19)  finger 서비스 비활성화"
systemctl stop finger
systemctl disable finger
ps -ef | grep finger

echo "U-20) Anonymous FTP 비활성화"
if [ -f /etc/vsftpd/vsftpd.conf ]
  then
    if [ `cat /etc/vsftpd/vsftpd.conf | grep -E "anonymous_enable" | wc -l` -lt 1 ]
     then
       echo "anonymous_enable=NO" >> /etc/vsftpd/vsftpd.conf
    else
       sed -i 's/.*anonymous_enable=.*/anonymous_enable=NO/g' /etc/vsftpd/vsftpd.conf
	fi
fi
if [ -f /etc/vsftpd.conf ]
  then
    if [ `cat /etc/vsftpd.conf | grep -E "anonymous_enable" | wc -l` -lt 1 ]
     then
       echo "anonymous_enable=NO" >> /etc/vsftpd.conf
    else
       sed -i 's/.*anonymous_enable=.*/anonymous_enable=NO/g' /etc/vsftpd.conf
	fi
fi
cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable

echo "U-21) r 계열 서비스 비활성화(모두 기본 비활성화)"
systemctl stop rpc-gssd.service
systemctl stop rpc-statd-notify.service
systemctl stop rpc_pipefs.target
systemctl stop rpcbind.socket
systemctl stop rpc-rquotad.service
systemctl stop rpc-statd.service
systemctl stop rpcbind.service

systemctl disable rpc-gssd.service
systemctl disable rpc-statd-notify.service
systemctl disable rpc_pipefs.target
systemctl disable rpcbind.socket
systemctl disable rpc-rquotad.service
systemctl disable rpc-statd.service
systemctl disable rpcbind.service

echo "U-22) cron 파일 소유자 및 권한 설정"
touch /etc/cron.allow
chown root:root /etc/cron.allow
chown root:root /etc/cron.deny
chmod 600 /etc/cron.allow
chmod 600/etc/cron.deny
ls -al /etc/cron.*

echo "U-23) Dos 공격에 취약한 서비스 비활성화 (xinet.d 해당없음)"
echo "U-24) NFS 서비스 비활성화(시스템에 따라 확인하여 재활성화 필요)"
systemctl stop nfs-server.service
systemctl disable nfs-server.service
echo "U-25) NFS접근 통제(/etc/exports 내용 확인 필요)"
echo "U-26) automountd 제거"
systemctl stop automountd.service
systemctl disable automountd.service

echo "U-27) /etc/xinet.d/ finger 서비스 확인 (설정파일 미존재)"

echo "U-28) NIS, NIS+ 서비스 점검(비활성화)"
systemctl stop NIS.service
systemctl stop NIS+.service
systemctl disable NIS.service
systemctl disable NIS+.service

echo "U-29) tftp, talk 서비스 비활성화 (조치되어있음)"
echo "U-30)  sendmail 점검 (미사용)"
echo "U-31) 스팸 메일 릴에이 제한(미사용)"
echo "U-32) 일반 사용자의 sendmail 실행 방지 (미사용)"
echo "U-33) DNS 보안버젼 패치 (미사용) name -V"
echo "U-34) DNS Zone Transfer 설정 (미사용) find / -name named.conf"

echo "U-35) Apache 디렉토리 리스팅 제거(아파치 사용시 확인 필요)"
sed -i 's/Options Indexes.*/Options none/g' /etc/httpd/conf/httpd.conf
echo "U-35) nginx 디렉토리 리스팅 제거"
sed -i 's/autoindex on/autoindex off/g' /etc/nginx/sites-available/*.*
sed -i 's/autoindex on/autoindex off/g' /etc/nginx/conf.d/*.*

echo "U-36) Aapache 웹 프로세스 권한 제한 (미사용)"
echo "U-37) Aapache 상위 디렉토리 접근 금지 (미사용)"
echo "U-38) Apache 불필요한 파일 제거(htdocs 매뉴얼 파일)"
rm -rf /etc/httpd/htdocs/manual
rm -rf /etc/httpd/manual
echo "U-39) Aapache 링크 사용 금지 (확인필요)"
echo "U-40) Aapache 파일 업로드 및 다운로드 제한 (확인필요)"
echo "U-41) Aapache 웹 서비스 영역의 분리 (확인필요)"
echo "U-61) ssh 원격 접속 허용 (사용중)"
echo "U-62) ftp 서비스 확인 vsftpd (미사용)"
echo "U-63) ftp 계정 shell 제한 (미사용 없음)"
echo "U-64) ftpuser 파일 소유자 및 권한 설정"
chown root:root /etc/vsftpd/ftpusers
chmod 600 /etc/vsftpd/ftpusers
ls -al /etc/vsftpd/ftpusers

echo "U-65) ftpusers 파일 설정 ftpuses 파일 root 계정 포함 여부 (없음)"
echo "U-66) at 파일 소유자 및 권한 설정"
touch /etc/at.allow
chown root /etc/cron.d/at.allow /etc/cron.d/at.deny /etc/at.allow /etc/at.deny /var/adm/cron/at.allow /var/adm/cron/at.deny
chmod 640 /etc/cron.d/at.allow /etc/cron.d/at.deny /etc/at.allow /etc/at.deny /var/adm/cron/at.allow /var/adm/cron/at.deny
ls -al /etc/at.*

echo "U-67) SNMP 서비스 구동 점검(미사용)"
echo "U-68) SNMP 서비스 Community string의 복잡성 설정(미사용)"
if [ -f /etc/snmp/snmpd.conf ]
  then
	if [ `cat /etc/snmp/snmpd.conf | grep -E 'com2sec.*public|com2sec.*private' | wc -l` -gt 0 ]
	then
		sed -i 's/com2sec.*/com2sec notConfigUser  default    SEC_LOTTE/g' /etc/snmp/snmpd.conf
		if [ `cat /etc/*-release | uniq | grep -E 'release 5|release 6' | wc -l` -gt 0 ]
			then
			  service snmpd restart && service snmpd stop
		else
			  systemctl restart snmpd && systemctl stop snmpd
		fi
	fi
fi

echo "U-69) 로그온 시 경고 메시지 제공(아래 두개파일 수동 설정필요)"
if [ -f /etc/motd ]
  then
    echo "********************* W  A  R  N  I  N  G  ! *********************" > /etc/motd
    echo "           All connections are monitored and recorded.            " >> /etc/motd
	echo "    Disconnect IMMEDIATELY if you are not an authorized user!     " >> /etc/motd
    echo "******************************************************************" >> /etc/motd
fi
if [ -f /etc/issue.net ]
    then
      echo "********************* W  A  R  N  I  N  G  ! *********************" > /etc/issue.net
	  echo "           All connections are monitored and recorded.            " >> /etc/issue.net
      echo "    Disconnect IMMEDIATELY if you are not an authorized user!     " >> /etc/issue.net
      echo "******************************************************************" >> /etc/issue.net
fi
if [ -f /etc/vsftpd/vsftpd.conf ]
    then
      sed -i 's/.*ftpd_banner=.*/ftpd_banner=*** WARNING! *** All connections are monitored and recorded. Disconnect IMMEDIATELY if you are not an authorized user!/g' /etc/vsftpd/vsftpd.conf
fi
if [ -f /etc/named.conf ]
	then
      echo "********************* W  A  R  N  I  N  G  ! *********************" >> /etc/named.conf
	  echo "           All connections are monitored and recorded.            " >> /etc/named.conf
      echo "    Disconnect IMMEDIATELY if you are not an authorized user!     " >> /etc/named.conf
      echo "******************************************************************" >> /etc/named.conf
fi
echo "cat /etc/issue.net"
echo "cat /etc/motd"
echo "cat /etc/named.conf"
echo "/etc/vsftpd/vsftpd.conf"

echo "U-70) NFS 설정파일 접근권한(미사용이나 조치 진행)"
chown root /etc/dfs/dfstab /etc/dfs/sharetab /etc/exports
chmod 644 /etc/dfs/dfstab /etc/dfs/sharetab /etc/exports
ls -al /etc/exports

echo "U-71) expn, vrfy 명령어 제한 snmp미사용이나 조치 진행"
if [ `ps -ef | grep sendmail | grep -v grep |wc -l` -ne 0 ]
  then 
    sed -i 's/.*O PrivacyOptions.*/O PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun/g' /etc/mail/sendmail.cf
    if [ `cat /etc/*-release | uniq | grep -E 'release 5|release 6' | wc -l` -gt 0 ]
      then
        service sendmail restart && service sendmail stop
      else
        systemctl restart sendmail && systemctl stop sendmail
    fi
fi
ps -ef | grep snmp

echo "U-42) 최신 보안패치 및 벤터 권고사항 적용 (시기에 맞게 보안패치 적용 수동 적용)"
echo "U-43) 로그의 정기적 검토 및 보고 (시기에 맞게 로그 정기 검토)"

echo "U-72) Apache 웹 서비스 정보 숨김(미사용)"

echo "U-73) 정책에 따른 시스템 로깅 설정(/etc/rsyslog.conf 설정)"
if [ -f /etc/rsyslog.conf ]
  then
    if [ `cat /etc/rsyslog.conf | grep "/var/log/messages" | wc -l` -gt 0 ]
	  then
	   sed -i 's/.*\/var\/log\/messages/\*\.info\;mail\.none\;authpriv\.none\;cron\.none                                                  	\/var\/log\/messages/g' /etc/rsyslog.conf
	else
	   echo "*.info;mail.none\;authpriv.none;cron.none                                                  	/var/log/messages" >> /etc/rsyslog.conf
	fi
    if [ `cat /etc/rsyslog.conf | grep "/var/log/secure" | wc -l` -gt 0 ]
	  then
	   sed -i 's/.*\/var\/log\/secure/authpriv\.\*                                                  	\/var\/log\/secure/g' /etc/rsyslog.conf
	else
	   echo "authpriv.*                                                  	/var/log/secure" >> /etc/rsyslog.conf
	fi
    if [ `cat /etc/rsyslog.conf | grep "/var/log/maillog" | wc -l` -gt 0 ]
	  then
	   sed -i 's/.*\/var\/log\/maillog/mail\.\*                                                  	\/var\/log\/maillog/g' /etc/rsyslog.conf
	else
	   echo "mail.*                                                  	/var/log/maillog" >> /etc/rsyslog.conf
	fi
    if [ `cat /etc/rsyslog.conf | grep "/var/log/cron" | wc -l` -gt 0 ]
	  then
	   sed -i 's/.*\/var\/log\/cron/cron\.\*                                                  	\/var\/log\/cron/g' /etc/rsyslog.conf
	else
	   echo "cron.*                                                  	/var/log/cron" >> /etc/rsyslog.conf
	fi
    if [ `cat /etc/rsyslog.conf | grep "/dev/console" | wc -l` -gt 0 ]
	  then
	   sed -i 's/.*\/dev\/console/\*\.alert                                                  	\/dev\/console/g' /etc/rsyslog.conf
	else
	   echo "*.alert                                                  	/dev/console" >> /etc/rsyslog.conf
	fi
    if [ `cat /etc/rsyslog.conf | grep "*$" | wc -l` -gt 0 ]
	  then
	   sed -i 's/.*\*$/\*\.emerg                                                  	\*/g' /etc/rsyslog.conf
	else
	   echo "*.emerg                                                  	*" >> /etc/rsyslog.conf
	fi
fi

touch /root/count1.txt
chattr +i /root/count1.txt
echo "취약점 조치가 완료 되었습니다. 실행 경로에 생성된 result.txt 파일을 복사 또는 이동하여 주십시오."
echo "스크립트 재 실행 시 조치 값이 사라지며 [이미 보안조치 스크립트를 실행 했습니다.] 라는 값으로 대체 됩니다."
fi
