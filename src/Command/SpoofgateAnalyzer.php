<?php

namespace App\Command;

use Email\Parse;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputArgument;

class SpoofgateAnalyzer extends Command {
    protected static $defaultName = 'app:spoofgate';
    
    protected function configure() {
        $this->setDescription('Analyze a list of domains for Spoofgate checks');
        $this->addArgument('list', InputArgument::REQUIRED, 'Domain CSV');
        $this->addArgument('out', InputArgument::REQUIRED, 'Path to output JSON');
    }
    private function extractSenderID($records) {
        $ret=[];
        foreach($records as $record) {
            if($record["type"]!=="TXT")
                continue;
            if(substr($record["txt"],0,6)==="spf2.0")
                $ret[]=$record["txt"];
        }
        return $ret;
    }
    private function extractSPF($records) {
        $ret=[];
        foreach($records as $record) {
            if($record["type"]!=="TXT")
                continue;
            if(substr($record["txt"],0,6)==="v=spf1")
                $ret[]=$record["txt"];
        }
        return $ret;
    }
    private function extractMX($records) {
        $ret=[];
        foreach($records as $record) {
            if($record["type"]!=="MX")
                continue;
            $ret[]=$record["target"];
        }
        return $ret;
    }
    private function extractA($records) {
        $ret=[];
        foreach($records as $record) {
            if($record["type"]!=="A")
                continue;
            $ret[$record["ip"]]=gethostbyaddr($record["ip"]);
        }
        return $ret;
    }
    private function extractAAAA($records) {
        $ret=[];
        foreach($records as $record) {
            if($record["type"]!=="AAAA")
                continue;
            $ret[$record["ipv6"]]=gethostbyaddr($record["ipv6"]);
        }
        return $ret;
    }
    private function extractCNAME($records) {
        $ret=[];
        foreach($records as $record) {
            if($record["type"]!=="CNAME")
                continue;
            $ret[]=$record["target"];
        }
        return $ret;
    }
    private function getDMARC($domain) {
        $ret=[];
        $records=dns_get_record("_dmarc.$domain",DNS_TXT);
        if($records===false || !is_array($records) || sizeof($records)==0) {
            //Recurse on the parent domain
            $components=explode(".",$domain);
            if(sizeof($components)==1) //No more left
                return $ret;
            array_shift($components);
            return $this->getDMARC(implode(".",$components));
        }
        foreach($records as $record) {
            if($record["type"]!=="TXT")
                continue;
            if(substr($record["txt"],0,8)==="v=DMARC1")
                $ret[]=$record["txt"];
        }
        return $ret;
    }
    private function stackHttp($url) {
        $guzzle = new \GuzzleHttp\Client();
        $stack=[];
        try {
        while(true) {
            $response=$guzzle->request("GET", $url, [
                "allow_redirects"=>false,
                "connect_timeout"=>5,
                "read_timeout"=>10,
            ]);
            $code=$response->getStatusCode();
            if($code==200 || $code>=400 || !$response->hasHeader("Location")) {
                $stack[]=[$code,$url,""];
                break;
            }
            $location=$response->getHeader("Location")[0];
            $stack[]=[$code,$url,$location];
            if(substr($location,0,7)==="http://" || substr($location,0,8)==="https://")
                $url=$location;
            else if(substr($location,0,1)==="/") { // relative to current URL base
                $parsed=parse_url($url);
                $url=$parsed["scheme"]."://".$parsed["host"].$location;
            } else
                throw new \Exception("Invalid location '$location'");
        }
        } catch(\Exception $e) {
            $stack[]=[null,$url,$e->getMessage()];
        }
        return $stack;
    }
    private function checkDomain($domain, OutputInterface $output) {
        $ret=[];
        $output->writeln("Checking domain $domain");
        $dns_all=[];
        //Get the record types we want. 46 is RRSIG, 43 is DS
        foreach([[DNS_A,false],[DNS_CNAME,false],[DNS_TXT,false],[DNS_NS,false],[DNS_AAAA,false],[DNS_MX,false],[43,true],[46,true]] as $dns_wanted_config) {
            $void=[]; //skip authns/addtl
            $records=dns_get_record($domain,$dns_wanted_config[0],$void,$void,$dns_wanted_config[1]);
            if($records===false || !is_array($records) || sizeof($records)==0)
                continue;
            $dns_all=array_merge($dns_all,$records);
        }
//        var_dump($dns_all);
        //$ret["dns_raw"]=$dns_all;
        $ret["spf"]=$this->extractSPF($dns_all);
        $ret["senderid"]=$this->extractSenderID($dns_all);
        $ret["mx"]=$this->extractMX($dns_all);
        $ret["dmarc"]=$this->getDMARC($domain);
        $ret["cname"]=$this->extractCNAME($dns_all);
        $ret["ipv4"]=$this->extractA($dns_all);
        $ret["ipv6"]=$this->extractAAAA($dns_all);
        $ret["http"]=$this->stackHttp("http://$domain");
        $ret["https"]=$this->stackHttp("https://$domain");
        return $ret;
    }
    
    protected function execute(InputInterface $input, OutputInterface $output) {
        $listFile=$input->getArgument("list","");
        if(!is_file($listFile))
            throw new \Exception("'$listFile' is not a valid file");
        $outFile=$input->getArgument("out","");
        $outFp=fopen($outFile,"w");
        if($outFp===false)
            throw new \Exception("Could not open '$outFile'");
        $emailParse=Parse::getInstance();
        
        $reader = new \PhpOffice\PhpSpreadsheet\Reader\Csv();
        $reader->setDelimiter(';');
        $reader->setEnclosure('');
        $reader->setSheetIndex(0);
        $list = $reader->load($listFile);
        $sheet = $list->getActiveSheet();
        $results=[];
        foreach ($sheet->getRowIterator(2) as $row) { //skip header
            $state=$sheet->getCell("A".$row->getRowIndex());
            $office=$sheet->getCell("B".$row->getRowIndex());
            $mail=$sheet->getCell("C".$row->getRowIndex());
            $url=$sheet->getCell("D".$row->getRowIndex());
            $output->writeln("Analyzing state $state office $office");
            $candidateDomains=[];
            //Parse and normalize (i.e. remove www. prefix) the domain URL
            $parsed_url=parse_url(trim($url));
            $host=$parsed_url["host"];
            if(substr($host,0,4)==="www.")
                $host=substr($host,4);
            $candidateDomains[]=$host;
            $candidateDomains[]="www.$host";
            //These here check how the DNS deals with non-existing domains
            $candidateDomains[]="thisdoesnotexist.$host";
            $candidateDomains[]="thisdoesnotexist.www.$host";
            
            //Parse the email address
            $parsed_mail=$emailParse->parse(trim($mail));
            $host=$parsed_mail["email_addresses"][0]["domain"];
            if(substr($host,0,4)==="www.")
                $host=substr($host,4);
            $candidateDomains[]=$host;
            $candidateDomains[]="www.$host";
            //These here check how the DNS deals with non-existing domains
            $candidateDomains[]="thisdoesnotexist.$host";
            $candidateDomains[]="thisdoesnotexist.www.$host";
            
            //Now remove duplicate domain suggestions
            $candidateDomains=array_unique($candidateDomains);

            foreach($candidateDomains as $domain) {
                if(array_key_exists($domain,$results))
                    continue;
                $results[$domain]=$this->checkDomain($domain,$output);
            }
        }
        fwrite($outFp,json_encode($results,JSON_PRETTY_PRINT));
        fclose($outFp);
        return Command::SUCCESS;
    }
}