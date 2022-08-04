#!/bin/bash
# Red Team Banorte


RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;93m'
BIBlue='\033[1;94m'
BIGreen='\033[1;92m'
NC='\033[0m'

SECONDS=0

usage(){
echo -e "\t${RED}Uso: ${BIGreen}$0 <Dirección IP> <Tipos de Escaneos>"
echo -e
echo -e "\t${BIGreen}Rapido	${BIBlue}:Busca los puertos abiertos rápidamente (15 segundos)"
echo -e "\t${BIGreen}Basico	${BIBlue}:Muestra los puertos rápido, luego realiza una exploración más exhaustiva en los puertos encontrados (5 minutos)"
echo -e "\t${BIGreen}Completo${BIBlue}:Analiza los puertos en rango completo, luego ejecuta una exploración exhaustiva de nuevos puertos (5 a 10 minutos)"
echo -e "\t${BIGreen}UDP	${BIBlue}:Ejecuta \"Basico\" en puertos UDP (5 minutos)"
echo -e "\t${BIGreen}Vulns	${BIBlue}:Busca Vulnerabilidades CVE en todos los puertos encontrados (5 a 15 minutos)"
echo -e "\t${BIGreen}Recon	${BIBlue}:Recomienda comandos de reconocimiento WEB o los ejecuta automáticamente (Instale GOBUSTER)"
echo -e "\t${BIGreen}Todo	${BIBlue}:Utiliza todos los escaneos anteriores (20 a 30 minutos)"
echo -e ""
exit 1
}

header(){
echo -e "${BIBlue}Banorte RedTeam"
echo -e ""
if [ "$2" == "Todo" ]; then

	echo -e "${YELLOW}Ejecutando todos los escaneos en $1"
else
	echo -e "${YELLOW}Corriendo un escaner $2 en $1"
fi

subnet=`echo "$1" | cut -d "." -f 1,2,3`".0"

checkPing=`checkPing $1`
nmapType="nmap -Pn"

: '
#nmapType=`echo "${checkPing}" | head -n 1`

if [ "$nmapType" != "nmap" ]; then
	echo -e "${NC}"
	echo -e "${YELLOW}No se detectó ping. Ejecutando con opción -Pn!"
	echo -e "${NC}"
fi
'

ttl=`echo "${checkPing}" | tail -n 1`
if [[  `echo "${ttl}"` != "nmap -Pn" ]]; then
	osType="$(checkOS $ttl)"
	echo -e "${NC}"
	echo -e "${GREEN}Es probable que el host esté ejecutando $osType"
	echo -e "${NC}"
fi

echo -e ""
echo -e ""
}

assignPorts(){
if [ -f nmap/Rapido_$1.nmap ]; then
	basicoPorts=`cat nmap/Rapido_$1.nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2`
fi

if [ -f nmap/Completo_$1.nmap ]; then
	if [ -f nmap/Rapido_$1.nmap ]; then
		todoPorts=`cat nmap/Rapido_$1.nmap nmap/Completo_$1.nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-1`
	else
		todoPorts=`cat nmap/Completo_$1.nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | head -c-1`
	fi
fi

if [ -f nmap/UDP_$1.nmap ]; then
	udpPorts=`cat nmap/UDP_$1.nmap | grep -w "open " | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2`
	if [[ "$udpPorts" == "Al" ]]; then
		udpPorts=""
	fi
fi
}

checkPing(){
pingTest=`ping -c 1 -W 3 $1 | grep ttl`
if [[ -z $pingTest ]]; then
	echo "nmap -Pn"
else
	echo "nmap"
	ttl=`echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2`
	echo "${ttl}"
fi
}

checkOS(){
if [ "$1" == 256 ] || [ "$1" == 255 ] || [ "$1" == 254 ]; then
        echo "OpenBSD/Cisco/Oracle"
elif [ "$1" == 128 ] || [ "$1" == 127 ]; then
        echo "Windows"
elif [ "$1" == 64 ] || [ "$1" == 63 ]; then
        echo "Linux"
else
        echo "Sistema Operativo Desconocido!"
fi
}

cmpPorts(){
oldIFS=$IFS
IFS=','
touch nmap/cmpPorts_$1.txt

for i in `echo "${todoPorts}"`
do
	if [[ "$i" =~ ^($(echo "${basicoPorts}" | sed 's/,/\|/g'))$ ]]; then
       	       :
       	else
       	        echo -n "$i," >> nmap/cmpPorts_$1.txt
       	fi
done

extraPorts=`cat nmap/cmpPorts_$1.txt | tr "\n" "," | head -c-1`
rm nmap/cmpPorts_$1.txt
IFS=$oldIFS
}

rapidoScan(){
echo -e "${GREEN}*****************${BIGreen}Escáner Rápido de Nmap${GREEN}*****************"
echo -e "${NC}"

$nmapType -T4 --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit --open -oN nmap/Rapido_$1.nmap $1
assignPorts $1

echo -e ""
echo -e ""
echo -e ""
}

basicoScan(){
echo -e "${GREEN}*****************${BIGreen}Iniciando Escaneo Básico de Nmap${GREEN}*****************"
echo -e "${NC}"

if [ -z `echo "${basicoPorts}"` ]; then
        echo -e "${YELLOW}Sin puertos en escaneo rápido."
else
	$nmapType -sCV -p`echo "${basicoPorts}"` -oN nmap/Basico_$1.nmap $1
fi

if [ -f nmap/Basico_$1.nmap ] && [[ ! -z `cat nmap/Basico_$1.nmap | grep -w "Información de OS:"` ]]; then
	serviceOS=`cat nmap/Basico_$1.nmap | grep -w "Información de OS:" | cut -d ":" -f 3 | cut -c2- | cut -d ";" -f 1 | head -c-1`
	if [[ "$osType" != "$serviceOS"  ]]; then
		osType=`echo "${serviceOS}"`
		echo -e "${NC}"
		echo -e "${NC}"
		echo -e "${GREEN}Detección de SO modificada a: $osType"
		echo -e "${NC}"
	fi
fi

echo -e ""
echo -e ""
echo -e ""
}

UDPScan(){
echo -e "${GREEN}*****************${BIGreen}Inicio de Escaneo Nmap UDP${GREEN}*****************"
echo -e "${NC}"

$nmapType -sU --max-retries 1 --open -oN nmap/UDP_$1.nmap $1
assignPorts $1

if [ ! -z `echo "${udpPorts}"` ]; then
        echo ""
        echo ""
        echo -e "${YELLOW}Hacer un escaneo de script en puertos UDP: `echo "${udpPorts}" | sed 's/,/, /g'`"
        echo -e "${NC}"
	if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
        	$nmapType -sCVU --script vulners --script-args mincvss=7.0 -p`echo "${udpPorts}"` -oN nmap/UDP_$1.nmap $1
	else
        	$nmapType -sCVU -p`echo "${udpPorts}"` -oN nmap/UDP_$1.nmap $1
	fi
fi

echo -e ""
echo -e ""
echo -e ""
}

fullScan(){
echo -e "${GREEN}*****************${BIGreen}Inicio de Escaneo Completo${GREEN}*****************"
echo -e "${NC}"

$nmapType -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v -oN nmap/Completo_$1.nmap $1
assignPorts $1

if [ -z `echo "${basicoPorts}"` ]; then
	echo ""
        echo ""
        echo -e "${YELLOW}Hacer un escaneo de scripts en todos los puertos"
        echo -e "${NC}"
        $nmapType -sCV -p`echo "${todoPorts}"` -oN nmap/Completo_$1.nmap $1
	assignPorts $1
else
	cmpPorts $1
	if [ -z `echo "${extraPorts}"` ]; then
        	echo ""
        	echo ""
		todoPorts=""
        	echo -e "${YELLOW}No hay nuevos puertos "
		rm nmap/Completo_$1.nmap
        	echo -e "${NC}"
	else
		echo ""
        	echo ""
        	echo -e "${YELLOW}Hacer un escaneo de scripts en puertos adicionales: `echo "${extraPorts}" | sed 's/,/, /g'`"
        	echo -e "${NC}"
        	$nmapType -sCV -p`echo "${extraPorts}"` -oN nmap/Completo_$1.nmap $1
		assignPorts $1
	fi
fi

echo -e ""
echo -e ""
echo -e ""
}

vulnsScan(){
echo -e "${GREEN}*****************${BIGreen}Escaneo de Vulnerabilidades con nmap${GREEN}*****************"
echo -e "${NC}"

if [ -z `echo "${todoPorts}"` ]; then
	portType="basico"
	ports=`echo "${basicoPorts}"`
else
	portType="todo"
	ports=`echo "${todoPorts}"`
fi


if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
	echo -e "${RED}Instale el script nmap 'vulners.nse':"
	echo -e "${RED}https://github.com/vulnersCom/nmap-vulners"
        echo -e "${RED}"
        echo -e "${RED}Omitiendo escaneo CVE!"
	echo -e "${NC}"
else
	echo -e "${YELLOW}Ejecutando Escaneo CVE en $portType puertos"
	echo -e "${NC}"
	$nmapType -sV --script vulners --script-args mincvss=7.0 -p`echo "${ports}"` -oN nmap/CVEs_$1.nmap $1
	echo ""
fi

echo ""
echo -e "${YELLOW}Ejecutando Escaneo de Vulnerabilidades en puertos $portType"
echo -e "${NC}"
$nmapType -sV --script vuln -p`echo "${ports}"` -oN nmap/Vulns_$1.nmap $1
echo -e ""
echo -e ""
echo -e ""
}

recon(){

reconRecommend $1 | tee nmap/Recon_$1.nmap

availableRecon=`cat nmap/Recon_$1.nmap | grep $1 | cut -d " " -f 1 | sed 's/.\///g; s/.py//g; s/cd/odat/g;' | sort -u | tr "\n" "," | sed 's/,/,\ /g' | head -c-2`

secs=30
count=0

reconCommand=""

if [ ! -z "$availableRecon"  ]; then
	while [ ! `echo "${reconCommand}"` == "!" ]; do
		echo -e "${YELLOW}"
		echo -e "¿Qué comandos te gustaría ejecutar?${NC}\nTodo (Por Defecto), $availableRecon, Omitir <!>\n"
		while [[ ${count} -lt ${secs} ]]; do
			tlimit=$(( $secs - $count ))
			echo -e "\rEjecutando Predeterminado en(${tlimit}) s: \c"
			read -t 1 reconCommand
			[ ! -z "$reconCommand" ] && { break ;  }
			count=$((count+1))
		done
		if [ "$reconCommand" == "Todo" ] || [ -z `echo "${reconCommand}"` ]; then
			runRecon $1 "Todo"
			reconCommand="!"
		elif [[ "$reconCommand" =~ ^($(echo "${availableRecon}" | tr ", " "|"))$ ]]; then
			runRecon $1 $reconCommand
			reconCommand="!"
		elif [ "$reconCommand" == "Omitir" ] || [ "$reconCommand" == "!" ]; then
			reconCommand="!"
			echo -e ""
			echo -e ""
			echo -e ""
		else
			echo -e "${NC}"
			echo -e "${RED}Elección incorrecta!"
			echo -e "${NC}"
		fi
	done
fi

}

reconRecommend(){
echo -e "${GREEN}*****************${BIGreen}Recomendaciones de reconocimiento${GREEN}*****************"
echo -e "${NC}"

oldIFS=$IFS
IFS=$'\n'

if [ -f nmap/Completo_$1.nmap ] && [ -f nmap/Basico_$1.nmap ]; then
	ports=`echo "${todoPorts}"`
	file=`cat nmap/Basico_$1.nmap nmap/Completo_$1.nmap | grep -w "open"`
elif [ -f nmap/Completo_$1.nmap ]; then
	ports=`echo "${todoPorts}"`
	file=`cat nmap/Rapido_$1.nmap nmap/Completo_$1.nmap | grep -w "open"`
elif [ -f nmap/Basico_$1.nmap ]; then
	ports=`echo "${basicoPorts}"`
	file=`cat nmap/Basico_$1.nmap | grep -w "open"`
else
	ports=`echo "${basicoPorts}"`
	file=`cat nmap/Basico_$1.nmap | grep -w "open"`

fi

if [[ ! -z `echo "${file}" | grep -i http` ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}Reconocimiento de Servidores web :"
	echo -e "${NC}"
fi

for line in $file; do
	if [[ ! -z `echo "${line}" | grep -i http` ]]; then
		port=`echo "${line}" | cut -d "/" -f 1`
		if [[ ! -z `echo "${line}" | grep -w "IIS"` ]]; then
			pages=".html,.asp,.php"
		else
			pages=".html,.php"
		fi
		if [[ ! -z `echo "${line}" | grep ssl/http` ]]; then
			#echo "sslyze --regular $1 | tee recon/sslyze_$1_$port.txt"
			echo "sslscan $1 | tee recon/sslscan_$1_$port.txt"
			echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 30 -e -k -x $pages -u https://$1:$port -o recon/gobuster_$1_$port.txt"
			echo "nikto -host https://$1:$port -ssl | tee recon/nikto_$1_$port.txt"
		else
			echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 30 -e -k -x $pages -u http://$1:$port -o recon/gobuster_$1_$port.txt"
			echo "nikto -host $1:$port | tee recon/nikto_$1_$port.txt"
		fi
		echo ""
	fi
done

if [ -f nmap/Basico_$1.nmap ]; then
	cms=`cat nmap/Basico_$1.nmap | grep http-generator | cut -d " " -f 2`
	if [ ! -z `echo "${cms}"` ]; then
		for line in $cms; do
			port=`cat nmap/Basico_$1.nmap | grep $line -B1 | grep -w "open" | cut -d "/" -f 1`
			if [[ "$cms" =~ ^(Joomla|WordPress|Drupal)$ ]]; then
				echo -e "${NC}"
				echo -e "${YELLOW}Reconocimiento CMS: "
				echo -e "${NC}"
			fi
			case "$cms" in
				Joomla!) echo "joomscan --url $1:$port | tee recon/joomscan_$1_$port.txt";;
				WordPress) echo "wpscan --url $1:$port --enumerate p | tee recon/wpscan_$1_$port.txt";;
				Drupal) echo "Escaneo droopescan drupal -u $1:$port | tee recon/droopescan_$1_$port.txt";;
			esac
		done
	fi
fi

if [[ ! -z `echo "${file}" | grep -w "445/tcp"` ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}Reconocimiento SMB :"
	echo -e "${NC}"
	echo "smbmap -H $1 | tee recon/smbmap_$1.txt"
	echo "smbclient -L \"//$1/\" -U \"guest\"% | tee recon/smbclient_$1.txt"
	if [[ $osType == "Windows" ]]; then
		echo "nmap -Pn -p445 --script vuln -oN recon/SMB_vulns_$1.txt $1"
	fi
	if [[ $osType == "Linux" ]]; then
		echo "enum4linux -a $1 | tee recon/enum4linux_$1.txt"
	fi
	echo ""
elif [[ ! -z `echo "${file}" | grep -w "139/tcp"` ]] && [[ $osType == "Linux" ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}Reconocimiento SMB:"
	echo -e "${NC}"
	echo "enum4linux -a $1 | tee recon/enum4linux_$1.txt"
	echo ""
fi


if [ -f nmap/UDP_$1.nmap ] && [[ ! -z `cat nmap/UDP_$1.nmap | grep open | grep -w "161/udp"` ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}Reconocimiento SNMP:"
	echo -e "${NC}"
	echo "snmp-check $1 -c public | tee recon/snmpcheck_$1.txt"
	echo "snmpwalk -Os -c public -v $1 | tee recon/snmpwalk_$1.txt"
	echo ""
fi

if [[ ! -z `echo "${file}" | grep -w "53/tcp"` ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}Reconocimiento DNS"
	echo -e "${NC}"
	echo "host -l $1 $1 | tee recon/hostname_$1.txt"
	echo "dnsrecon -r $subnet/24 -n $1 | tee recon/dnsrecon_$1.txt"
	echo "dnsrecon -r 127.0.0.0/24 -n $1 | tee recon/dnsrecon-local_$1.txt"
	echo ""
fi

if [[ ! -z `echo "${file}" | grep -w "1521/tcp"` ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}Reconocimiento Oracle \"Exc. from Default\":"
	echo -e "${NC}"
	echo "cd /opt/odat/;#$1;"
	echo "./odat.py sidguesser -s $1 -p 1521"
	echo "./odat.py passwordguesser -s $1 -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt"
	echo "cd -;#$1;"
	echo ""
fi

IFS=$oldIFS

echo -e ""
echo -e ""
echo -e ""
}

runRecon(){
echo -e ""
echo -e ""
echo -e ""
echo -e "${GREEN}*****************${BIGreen}Ejecución de comandos de reconocimiento${GREEN}*****************"
echo -e "${NC}"

oldIFS=$IFS
IFS=$'\n'

if [[ ! -d recon/ ]]; then
        mkdir recon/
fi

if [ "$2" == "Todo" ]; then
	reconCommands=`cat nmap/Recon_$1.nmap | grep $1 | grep -v odat`
else
	reconCommands=`cat nmap/Recon_$1.nmap | grep $1 | grep $2`
fi

for line in `echo "${reconCommands}"`; do
	currentScan=`echo $line | cut -d " " -f 1 | sed 's/.\///g; s/.py//g; s/cd/odat/g;' | sort -u | tr "\n" "," | sed 's/,/,\ /g' | head -c-2`
	fileName=`echo "${line}" | awk -F "recon/" '{print $2}' | head -c-1`
	if [ ! -z recon/`echo "${fileName}"` ] && [ ! -f recon/`echo "${fileName}"` ]; then
		echo -e "${NC}"
		echo -e "${YELLOW}Comenzando Escaneo $currentScan"
		echo -e "${NC}"
		echo $line | /bin/bash
		echo -e "${NC}"
		echo -e "${YELLOW}Escaneo Terminado $currentScan"
		echo -e "${NC}"
		echo -e "${YELLOW}=============================="
	fi
done

IFS=$oldIFS

echo -e ""
echo -e ""
echo -e ""
}

footer(){

echo -e "${GREEN}*****************${BIGreen}Terminado todos los escaneos de Nmap${GREEN}*****************"
echo -e "${NC}"
echo -e ""

if (( $SECONDS > 3600 )) ; then
    let "horas=SECONDS/3600"
    let "minutos=(SECONDS%3600)/60"
    let "segundos=(SECONDS%3600)%60"
    echo -e "${YELLOW}Completado en $horas hora(s), $minutos minuto(s) y $segundos segundo(s)"
elif (( $SECONDS > 60 )) ; then
    let "minutos=(SECONDS%3600)/60"
    let "segundos=(SECONDS%3600)%60"
    echo -e "${YELLOW}Completado en $minutos minuto(s) y $segundos segundo(s)"
else
    echo -e "${YELLOW}Completado en $SECONDS segundo(s)"
fi
echo -e ""
}

if (( "$#" != 2 )); then
	usage
fi

if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	:
else
	echo -e "${RED}"
	echo -e "${RED} IP Invalida!"
	echo -e "${RED}"
	usage
fi

if [[ "$2" =~ ^(Rapido|Basico|UDP|Completo|Vulns|Recon|Todo)$ ]]; then
	if [[ ! -d $1 ]]; then
	        mkdir $1
	fi

	cd $1

	if [[ ! -d nmap/ ]]; then
	        mkdir nmap/
	fi

	assignPorts $1

	header $1 $2

	case "$2" in
		Rapido) rapidoScan $1;;
		Basico)	if [ ! -f nmap/Rapido_$1.nmap ]; then rapidoScan $1; fi
			basicoScan $1;;
		UDP) 	UDPScan $1;;
		Completo) 	fullScan $1;;
		Vulns) 	if [ ! -f nmap/Rapido_$1.nmap ]; then rapidoScan $1; fi
			vulnsScan $1;;
		Recon) 	if [ ! -f nmap/Rapido_$1.nmap ]; then rapidoScan $1; fi
			if [ ! -f nmap/Basico_$1.nmap ]; then basicoScan $1; fi
			recon $1;;
		Todo)	rapidoScan $1
			basicoScan $1
			UDPScan $1
			fullScan $1
			vulnsScan $1
			recon $1;;
	esac

	footer
else
	echo -e "${RED}"
	echo -e "${RED}¡Tipo de Escaneo Invalido!"
	echo -e "${RED}"
	usage
fi
