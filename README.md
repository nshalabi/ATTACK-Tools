# ATT&amp;CK™-Tools
_Utilities for MITRE™ ATT&amp;CK™_

This repository contains the following:

* **ATT&amp;CK™ Data Model:** a relational data model for ATT&amp;CK™ and STIX™ (SQLite for simplicity and portability, support for other relational databases is under development).
* **ATT&amp;CK™ View:** an adversary emulation planning tool.

_**DISCLAIMER:** The current version is under development and is released for feedback, you can send  me feedback through GitHub or directly by email at **nader@nosecurecode.com**_

# Content

* Release Notes.
* Preview of ATT&amp;CK™ View.
* The ATT&amp;CK™ Data Model
* Accessing ATT&amp;CK™ Data with SQL.

# Release Notes

* Password of archives is **password**
* There are 32 and 64-bit builds (32.zip and 64.zip)
* ATT&amp;CK™ View database is bundled within the same archive (32.zip and 64.zip) and must be located at same location as the executable
* All executables are **digitally signed**
* ATT&amp;CK™ View **IS FREE**
* All executables are **packed using Themida** (https://www.oreans.com/themida.php)

# Preview of ATT&CK™ View

ATT&amp;CK™ View comes bundled with a full adversary emulation plan for APT3 developed by MITRE™ (SOURCE : https://attack.mitre.org/wiki/Adversary_Emulation_Plans)

![ATT&amp;CK™ View](https://nosecurecode.blog/wp-content/uploads/2018/08/AV1.png "ATT&amp;CK™ View")

**Testing Guideline Editor**

![ATT&amp;CK™ View](https://nosecurecode.blog/wp-content/uploads/2018/08/AV6.png "ATT&amp;CK™ View")

![ATT&amp;CK™ View](https://nosecurecode.blog/wp-content/uploads/2018/08/AV7.png "ATT&amp;CK™ View")

**APT3 Plan Exported to Excel**

![ATT&amp;CK™ View](https://nosecurecode.blog/wp-content/uploads/2018/08/AV4.png "ATT&amp;CK™ View")

**Plan Coverage View**

![ATT&amp;CK™ View](https://nosecurecode.blog/wp-content/uploads/2018/08/AV2.png "ATT&amp;CK™ View")

**Content Search**

![ATT&amp;CK™ View](https://nosecurecode.blog/wp-content/uploads/2018/08/AV3.png "ATT&amp;CK™ View")

# The Data Model

The following is a conceptual model that can be implemented using any database technology (The _attack_view_db_structure.sql_ is a good starting point).

![ATT&amp;CK™ Data Model](https://nosecurecode.blog/wp-content/uploads/2018/09/ATTACKDataModel.png "ATT&amp;CK™ Data Model")

# Accessing ATT&amp;CK™ Data with SQL
To have a better understanding about the database structure, following is  a list of sample SQL queries used to read ATT&amp;CK™. (There are many SQLite management tools, free and paid, runs on Windows, macOS Linux and can be used to access the database content and run SQL queries to extract the data).

*Some output truncated for brevity*

### Get the list of ATT&amp;CK™ techniques

**SQL**

`SELECT name
FROM sdos_object
WHERE type IS "attack-pattern";`

**OUTPUT**

<table>
<tr><th>name</th></tr>
<tr><td>.bash_profile and .bashrc</td></tr>
<tr><td>Access Token Manipulation</td></tr>
<tr><td>Accessibility Features</td></tr>
<tr><td>Account Discovery</td></tr>
<tr><td>Account Manipulation</td></tr>
<tr><td>...</td></tr></table>

### Get the list of ATT&amp;CK™ techniques names with their STIX 2.0 identifier

**SQL**

`SELECT id, name
FROM sdos_object
WHERE type IS "attack-pattern";`

**OUTPUT**

<table>
<tr><th>id</th><th>name</th></tr>
<tr><td>attack-pattern--01df3350-ce05-4bdf-bdf8-0a919a66d4a8</td><td>.bash_profile and .bashrc</td></tr>
<tr><td>attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48</td><td>Access Token Manipulation</td></tr>
<tr><td>attack-pattern--9b99b83a-1aac-4e29-b975-b374950551a3</td><td>Accessibility Features</td></tr>
<tr><td>attack-pattern--72b74d71-8169-42aa-92e0-e7b04b9f5a08</td><td>Account Discovery</td></tr>
<tr><td>attack-pattern--a10641f4-87b4-45a3-a906-92a149cb2c27</td><td>Account Manipulation</td></tr>
<tr><td colspan="2">...</td></tr>
</table>

*The* **id** *field is a unique key that will be used frequently in many SQL queries*

The external references are stored in external_references table, since one ATT&amp;CK™ technique can have one or more references, the link between the two tables is the technique identifier (check previous query), I will list multiple ways to access the external references

### Get the list of ATT&amp;CK™ techniques with external names

**SQL**

```
SELECT name, external_id
FROM sdos_object
       INNER JOIN external_references ON sdos_object.id = external_references.fk_object_id
WHERE sdos_object.type IS "attack-pattern"
  AND external_references.source_name IS "mitre-attack";
```

**OUTPUT**

<table>
<tr><th>name</th><th>external_id</th></tr>
<tr><td>.bash_profile and .bashrc</td><td>T1156</td></tr>
<tr><td>Access Token Manipulation</td><td>T1134</td></tr>
<tr><td>Accessibility Features</td><td>T1015</td></tr>
<tr><td>Account Discovery</td><td>T1087</td></tr>
<tr><td>Account Manipulation</td><td>T1098</td></tr>
<tr><td colspan="2">...</td></tr>
</table>

### List all ATT&amp;CK™ techniques associated with "Windows" platform 

**SQL**

```
SELECT name, external_id
FROM sdos_object
       INNER JOIN external_references ON sdos_object.id = external_references.fk_object_id
WHERE sdos_object.type IS "attack-pattern"
  AND x_mitre_platforms_windows IS "true"
  AND external_references.source_name IS "mitre-attack";
```

**OUTPUT**

<table>
<tr><th>name</th><th>external_id</th></tr>
<tr><td>Access Token Manipulation</td><td>T1134</td></tr>
<tr><td>Accessibility Features</td><td>T1015</td></tr>
<tr><td>Account Discovery</td><td>T1087</td></tr>
<tr><td>Account Manipulation</td><td>T1098</td></tr>
<tr><td>AppCert DLLs</td><td>T1182</td></tr>
<tr><td colspan="2">...</td></tr>
</table>

### List all Malware objects along with their description

**SQL**

```
SELECT name, description from sdos_object WHERE type IS "malware";
```

**OUTPUT**

<table>
<tr><th>name</th><th>description</th></tr>
<tr><td>3PARA RAT</td><td>3PARA RAT is a remote access tool (RAT) programmed in C++ that has been used by Putter Panda. (Citation: CrowdStrike Putter Panda)<br/><br/>Aliases: 3PARA RAT</td></tr>
<tr><td>4H RAT</td><td>4H RAT is malware that has been used by Putter Panda since at least 2007. (Citation: CrowdStrike Putter Panda)<br/><br/>Aliases: 4H RAT</td></tr>
<tr><td>ADVSTORESHELL</td><td>ADVSTORESHELL is a spying backdoor that has been used by APT28 from at least 2012 to 2016. It is generally used for long-term espionage and is deployed on targets deemed interesting after a reconnaissance phase. (Citation: Kaspersky Sofacy) (Citation: ESET Sednit Part 2)<br/><br/>Aliases: ADVSTORESHELL, NETUI, EVILTOSS, AZZY, Sedreco</td></tr>
<tr><td>ASPXSpy</td><td>ASPXSpy is a Web shell. It has been modified by Threat Group-3390 actors to create the ASPXTool version. (Citation: Dell TG-3390)<br/><br/>Aliases: ASPXSpy, ASPXTool</td></tr>
<tr><td>Agent.btz</td><td>Agent.btz is a worm that primarily spreads itself via removable devices such as USB drives. It reportedly infected U.S. military networks in 2008. (Citation: Securelist Agent.btz)<br/><br/>Aliases: Agent.btz</td></tr>
<tr><td colspan="2">...</td></tr>
</table>

### List all Adversaries (intrusion-sets) along with their description

**SQL**

```
SELECT name, description from sdos_object WHERE type IS "intrusion-set";
```

**OUTPUT**

<table>
<tr><th>name</th><th>description</th></tr>
<tr><td>APT1</td><td>APT1 is a Chinese threat group that has been attributed to the 2nd Bureau of the People’s Liberation Army (PLA) General Staff Department’s (GSD) 3rd Department, commonly known by its Military Unit Cover Designator (MUCD) as Unit 61398. (Citation: Mandiant APT1)</td></tr>
<tr><td>APT12</td><td>APT12 is a threat group that has been attributed to China. (Citation: Meyers Numbered Panda)</td></tr>
<tr><td>APT16</td><td>APT16 is a China-based threat group that has launched spearphishing campaigns targeting Japanese and Taiwanese organizations. (Citation: FireEye EPS Awakens Part 2)</td></tr>
<tr><td>APT17</td><td>APT17 is a China-based threat group that has conducted network intrusions against U.S. government entities, the defense industry, law firms, information technology companies, mining companies, and non-government organizations. (Citation: FireEye APT17)</td></tr>
<tr><td>APT18</td><td>APT18 is a threat group that has operated since at least 2009 and has targeted a range of industries, including technology, manufacturing, human rights groups, government, and medical. (Citation: Dell Lateral Movement)</td></tr>
<tr><td colspan="2">...</td></tr>
</table>

### List all Tools and Malware used by a certain Adversary

All STIX 2.0 Domain Objects (SDO) relations are stored in *"relatioship"* table. The following query is a nested query used to get the tools/malware used by APT3:

**SQL**

```
SELECT name, description
FROM sdos_object
WHERE (type IS "malware" OR type IS "tool") -- Query for tools or malware
  AND id IN (SELECT target_ref -- filter tools/malware associated with APT3
             FROM relationship
             WHERE relationship_type IS "uses" -- Source "uses" Target
               AND source_ref IS -- Source is APT3 identifier
                   "intrusion-set--0bbdf25b-30ff-4894-a1cd-49260d0dd2d9");
```

**OUTPUT**

<table>
<tr><th>name</th><th>description</th></tr>
<tr><td>OSInfo</td><td>OSInfo is a custom tool used by APT3 to do internal discovery on a victim&#39;s computer and network.  (Citation: Symantec Buckeye)<br/><br/>Aliases: OSInfo</td></tr>
<tr><td>PlugX</td><td>PlugX is a remote access tool (RAT) that uses modular plugins. (Citation: Lastline PlugX Analysis) It has been used by multiple threat groups. (Citation: FireEye Clandestine Fox Part 2) (Citation: New DragonOK) (Citation: Dell TG-3390)<br/><br/>Aliases: PlugX, Sogu, Kaba, Korplug</td></tr>
<tr><td>RemoteCMD</td><td>RemoteCMD is a custom tool used by APT3 to execute commands on a remote system similar to SysInternal&#39;s PSEXEC functionality.  (Citation: Symantec Buckeye)<br/><br/>Aliases: RemoteCMD</td></tr>
<tr><td>SHOTPUT</td><td>SHOTPUT is a custom backdoor used by APT3. (Citation: FireEye Clandestine Wolf)<br/><br/>Aliases: SHOTPUT, Backdoor.APT.CookieCutter, Pirpi</td></tr>
<tr><td>schtasks</td><td>schtasks is used to schedule execution of programs or scripts on a Windows system to run at a specific date and time. (Citation: TechNet Schtasks)<br/><br/>Aliases: schtasks, schtasks.exe</td></tr>
<tr><td colspan="2">...</td></tr>
</table>
