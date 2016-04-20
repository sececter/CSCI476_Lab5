/*
 * A program to simulate a network instrusion detection system (IDS).
 * CSCI 476 - Lab 5 - Montana State University
 */
package csci467_lab5;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.sigtran.Sctp;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.Rtp;

/**
 * Main driver class of program to simulate IDS
 * @author Matthew Rohrlach
 */
public class IDS {

    /**
     * Global Variables
     */
    
    int violationCount = 0;
    
    //Packet Headers
    final Ip4 ip4Header = new Ip4();
    final Tcp tcpHeader = new Tcp();
    final Udp udpHeader = new Udp();
    final Payload payloadHeader = new Payload();
    final Ip6 ip6Header = new Ip6();
    final Http httpHeader = new Http();
    final Html htmlHeader = new Html();
    final Rtp rtpHeader = new Rtp();
    final Sctp sctpHeader = new Sctp();
    final Ethernet ethernetHeader = new Ethernet();
    final Arp arpHeader = new Arp();
    final Icmp icmpHeader = new Icmp();
    
    
    /**
     * Static starting point, checks arguments and runs non-static go instance
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        boolean done = false;
        
        String policyFilePath;
        String pcapFilePath;
        
        //Take arguments as file paths
        if (args.length >= 2){
            if (args.length > 2){
                System.out.println("Too many arguments! Only accepting first two.");
            }
            policyFilePath = args[0];
            pcapFilePath = args[1];
        }
        
        //Read in file path argument
        else {
            //Handle non-existent argument
            policyFilePath = JOptionPane.showInputDialog(null, "No policy file argument found! What is the path to "
                            + "the .policy file (q to quit)?");
            if (policyFilePath.equals("q")){
                done = true;
            }
            else if (policyFilePath.equals("")){
                policyFilePath = "policy1.policy";
            }
            
            //Handle non-existent argument
            pcapFilePath = JOptionPane.showInputDialog(null, "No PCAP file argument found! What is the path to "
                            + "the .pcap file (q to quit)?");
            if (pcapFilePath.equals("q")){
                done = true;
            }
            else if (pcapFilePath.equals("")){
                pcapFilePath = "trace1.pcap";
            }
        }
        
        if (!done){
            //Create new instance of driving method
            new IDS().go(policyFilePath, pcapFilePath);
        }
    }
    
    /**
     * High-level logic to build IDS in a non-static method
     * @param policyFilePath
     * @param pcapFilePath 
     */
    public void go(String policyFilePath, String pcapFilePath){

        //Create policy object from file path
        Policy argPolicy = new Policy(policyFilePath);
        processPcap(argPolicy, pcapFilePath);
        
        //Run again on reverse direction packets
        argPolicy.flip();
        processPcap(argPolicy, pcapFilePath);
        
        
        //Print the total violations of this combination
        System.out.println(violationCount + " violation(s) found!");
    }
    
    /**
     * Process a pcap file with a policy in mind
     * @param argPolicy
     * @param pcapFilePath 
     */
    public void processPcap(Policy argPolicy, String pcapFilePath){
        //Open pcap file from file path
        StringBuilder errorString = new StringBuilder();
        Pcap pcapFile = Pcap.openOffline(pcapFilePath, errorString);
        
        //Try again if pcap cannot be found, appending file extension
        if (pcapFile == null){
            pcapFile = Pcap.openOffline(pcapFilePath+".pcap", errorString);
            if (pcapFile == null){
                System.err.println("File read error!\n");
                return;
            }
        }
        
        //Create pointer to a packet, 
        PcapPacket currPacket;
        currPacket = new PcapPacket(JMemory.POINTER);

        //This is the main loop to drive packet inspection in the .pcap file
        while (pcapFile.nextEx(currPacket) == Pcap.NEXT_EX_OK){
            String violation = "Violation found!\n"+argPolicy.name+"\n";
        
            //First, test for the proper protocol if in stateless mode
            boolean statelessProceed = false;
            if (argPolicy.type.equals("stateless")){
                if (properProtocol(argPolicy, currPacket) && currPacket.hasHeader(ip4Header)){
                    violation+=(argPolicy.protocol+" == "+argPolicy.protocol+"\n");
                    statelessProceed = true;
                }
                else {
                    //Do nothing
                }
            }
            
            //Continue inspection if stateful or if stateless passed the protocol check
            //Deny inspection if there is no ip4 traffic in this packet
            if ((argPolicy.type.equals("stateful") || statelessProceed) && currPacket.hasHeader(ip4Header)){
                
                //Check destination address against host address
                String destinationAddress = FormatUtils.ip(ip4Header.destination());
                if (argPolicy.host.equals(destinationAddress) || argPolicy.host.equals("any")){
                    violation+=(destinationAddress+" == "+argPolicy.host+"\n");
                    
                    //Check destination port against host port
                    String destinationPort = "";
                    //Ensure that a port can be found or set without a policy protocol
                    if (argPolicy.protocol == null){
                            if (currPacket.hasHeader(tcpHeader)){
                                destinationPort = Integer.toString(tcpHeader.destination());
                            }
                            else if (currPacket.hasHeader(udpHeader)){
                                destinationPort = Integer.toString(udpHeader.destination());
                            }
                            else{
                                destinationPort = "any";
                            }
                        }
                    //Take the destination port from the proper header, otherwise
                    else if (argPolicy.protocol.equals("tcp")){
                        destinationPort = Integer.toString(tcpHeader.destination());
                    }
                    else if (argPolicy.protocol.equals("udp")){
                        destinationPort = Integer.toString(udpHeader.destination());
                    }
                    
                    //Perform the check
                    if (argPolicy.host_port.equals(destinationPort) || argPolicy.host_port.equals("any")){
                        violation+=(destinationPort+" == "+argPolicy.host_port+"\n");
                        
                        //Check the source port against the policy's attacker port
                        String sourcePort = "";
                        //Ensure a port can be found without a protocol set in the policy
                        if (argPolicy.protocol == null){
                            if (currPacket.hasHeader(tcpHeader)){
                                sourcePort = Integer.toString(tcpHeader.source());
                            }
                            else if (currPacket.hasHeader(udpHeader)){
                                sourcePort = Integer.toString(udpHeader.source());
                            }
                            else{
                                sourcePort = "any";
                            }
                        }
                        //Take the port from the proper header, otherwise
                        else if (argPolicy.protocol.equals("tcp")){
                        sourcePort = Integer.toString(tcpHeader.source());
                        }
                        else if (argPolicy.protocol.equals("udp")){
                            sourcePort = Integer.toString(udpHeader.source());
                        }
                        
                        //Perform the check
                        if (argPolicy.attacker_port.equals(sourcePort) || argPolicy.attacker_port.equals("any")){
                            violation+=(sourcePort+" == "+argPolicy.attacker_port+"\n");
                            
                            //Check the source address against the policy's attacker address
                            String sourceAddress = FormatUtils.ip(ip4Header.source());
                            //Perform the check
                            if (argPolicy.attacker.equals(sourceAddress) || argPolicy.attacker.equals("any")){
                                violation+=(sourceAddress+" == "+argPolicy.attacker+"\n");
                                
                                //Now that we match on all criteria, inspect the packet for violations
                                Matcher matcher;
                                boolean foundViolation = false;
                                String lastViolation = "";
                                //Turn the packet into a UTF8 string and inspect it with the regex pattern given
                                String packetString = currPacket.getUTF8String(0, currPacket.size());
                                
                                //Check for a to_host violation
                                if (argPolicy.flipped == false){
                                    for(int i = 0; i < argPolicy.to_hosts.size(); i++){
                                        matcher = argPolicy.to_hosts.get(i).matcher(packetString);
                                        if(matcher.find()){
                                            if (!lastViolation.equals(("Violation: to_host rule \""+argPolicy.to_hosts.get(i).pattern()+"\"!\n"))){
                                                alertBox("Violation found (to_host rule: \""+argPolicy.to_hosts.get(i).pattern()+"\")!");
                                                violation+=("Violation: to_host rule \""+argPolicy.to_hosts.get(i).pattern()+"\"!\n");
                                                lastViolation = ("Violation: to_host rule \""+argPolicy.to_hosts.get(i).pattern()+"\"!\n");
                                                foundViolation = true;
                                                violationCount++;
                                            }
                                        }
                                    }
                                }
                                
                                //Check for a from_host violation (flipped actors)
                                else {
                                    for(int i = 0; i < argPolicy.from_hosts.size(); i++){
                                        matcher = argPolicy.from_hosts.get(i).matcher(packetString);
                                        if(matcher.find()){
                                            if (!lastViolation.equals(("Violation: from_host rule \""+argPolicy.from_hosts.get(i).pattern()+"\"!\n"))){
                                                alertBox("Violation found (from_host rule: \""+argPolicy.from_hosts.get(i).pattern()+"\")!");
                                                violation+=("Violation: from_host rule \""+argPolicy.from_hosts.get(i).pattern()+"\"!\n");
                                                lastViolation = ("Violation: from_host rule \""+argPolicy.from_hosts.get(i).pattern()+"\"!\n");
                                                foundViolation = true;
                                                violationCount++;
                                            }
                                        }
                                    }
                                }
                                
                                if(foundViolation){
                                    System.out.println(violation+"\n");
                                }
                            }
                        }
                    }
                }
            }
            
            else {
                //Do nothing
            }
        }
    }
    
    /**
     * Take in a string, turn it into a JOptionPane message dialog
     * @param alertText 
     */
    public void alertBox(String alertText){
        JOptionPane.showMessageDialog(null, alertText);
    }
    
    /**
     * Determine if a packet has the proper protocol for a given policy
     * @param policyToTest
     * @param packetToTest
     * @return 
     */
    public boolean properProtocol(Policy policyToTest, PcapPacket packetToTest){
        
        if (policyToTest.protocol.equals("any")){
            return true;
        }
        else if (policyToTest.protocol.equals("tcp") && packetToTest.hasHeader(tcpHeader)){
            return true;
        }
        else if (policyToTest.protocol.equals("udp") && packetToTest.hasHeader(udpHeader)){
            return true;
        }
        else if (policyToTest.protocol.equals("ip4") && packetToTest.hasHeader(ip4Header)){
            return true;
        }
        else if (policyToTest.protocol.equals("payload") && packetToTest.hasHeader(payloadHeader)){
            return true;
        }
        else if (policyToTest.protocol.equals("arp") && packetToTest.hasHeader(arpHeader)){
            return true;
        }
        else if (policyToTest.protocol.equals("ethernet") && packetToTest.hasHeader(ethernetHeader)){
            return true;
        }
        else if (policyToTest.protocol.equals("icmp") && packetToTest.hasHeader(icmpHeader)){
            return true;
        }
        else if (policyToTest.protocol.equals("ip6") && packetToTest.hasHeader(ip6Header)){
            return true;
        }
        else if (policyToTest.protocol.equals("rtp") && packetToTest.hasHeader(rtpHeader)){
            return true;
        }
        else if (policyToTest.protocol.equals("sctp") && packetToTest.hasHeader(sctpHeader)){
            return true;
        }
        else{
            return false;
        }
    }
}

//***************************************************************************************

/**
 * Policy object, may be stateful or stateless, with various fields and an ability to reverse direction
 * @author Matthew Rohrlach
 */
class Policy{
    public String filePath;
    public String host;
    public String name;
    public String type;
    public String host_port;
    public String attacker_port;
    public String attacker;
    public String protocol;
    public ArrayList<Pattern> from_hosts = new ArrayList<>();
    public ArrayList<Pattern> to_hosts = new ArrayList<>();
    
    public boolean flipped;
    
    
    public Policy(String filePathIn){
        filePath = filePathIn;
        flipped = false;
        processPolicy();
    }
    
    /**
     * Read the policy file at path into an object of class Policy
     */
    private void processPolicy(){
        try {
            File policyFile = new File(filePath);
            Scanner scan = new Scanner(policyFile);
            String thisLine;
            
            while(scan.hasNextLine()){
                thisLine = scan.nextLine();
                
                if (thisLine.contains("host=") && !thisLine.contains("_")){
                    host = thisLine.substring(5);
                    //System.out.println(host);
                }
                else if (thisLine.contains("name=")){
                    name = thisLine.substring(5);
                    //System.out.println(name);
                }
                else if (thisLine.contains("type=")){
                    type = thisLine.substring(5);
                    //System.out.println(type);
                }
                else if (thisLine.contains("proto=")){
                    protocol = thisLine.substring(6);
                    //System.out.println(protocol);
                }
                else if (thisLine.contains("attacker=")){
                    attacker = thisLine.substring(9);
                    //System.out.println(attacker);
                }
                else if (thisLine.contains("attacker_port=")){
                    attacker_port = thisLine.substring(14);
                    //System.out.println(attacker_port);
                }
                else if (thisLine.contains("host_port=")){
                    host_port = thisLine.substring(10);
                    //System.out.println(host_port);
                }
                else if (thisLine.contains("from_host=")){
                    String subbedString = thisLine.substring(11,thisLine.lastIndexOf('"'));
                    from_hosts.add(Pattern.compile(subbedString));
                    //System.out.println(from_hosts.get(from_hosts.size()-1).pattern());
                }
                else if (thisLine.contains("to_host=")){
                    String subbedString = thisLine.substring(9,thisLine.lastIndexOf('"'));
                    to_hosts.add(Pattern.compile(subbedString));
                    //System.out.println(to_hosts.get(to_hosts.size()-1).pattern());
                }
            }
        } 
        catch (FileNotFoundException ex) {
            if (!filePath.contains(".policy")){
                filePath = filePath+".policy";
                processPolicy();
            }
            else{
                System.err.println("File not found!");
                Logger.getLogger(Policy.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    /**
     * Flip the direction of the policy, to test 'from' rules
     */
    public void flip(){
        
        if (!flipped){
            flipped = true;
        }
        else {
            flipped = false;
        }
        
        String tempHost = host;
        String tempHostPort = host_port;
        
        host = attacker;
        host_port = attacker_port;
        
        attacker = tempHost;
        attacker_port = tempHostPort;
        
    }
}