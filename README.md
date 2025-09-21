# ATT&CK™ Tools 🛡️

[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)
![GitHub last commit](https://img.shields.io/github/last-commit/nshalabi/ATTACK-Tools)
![GitHub stars](https://img.shields.io/github/stars/nshalabi/ATTACK-Tools?style=social)

Utilities for working with the **MITRE™ ATT&CK™ framework**, including a relational data model and an adversary emulation planning tool.

---

### Repository Content

- **ATT&CK™ Data Model** – relational schema for representing MITRE™ ATT&CK data, enriched with Red Canary ATOMIC™ tests
- **ATT&CK™ View** – adversary emulation planning tooleee.

---

# 📑 Content

- [Release Notes](#release-notes)
- [Overview](#overview)
- [The ATT&CK™ Data Model](#the-attck-data-model)
- [Accessing ATT&CK™ Data with SQL](#accessing-attck-data-with-sql)
- [Additional Resources](#additional-resources)
- [Support](#support)
- [License](#license)
- [Contact](#contact)

---

# 📝 Release Notes

- **attack_view_db_structure.sql** and **attack_view_db_data.sql** – scripts to build SQLite database structure and load data.
- **enterprise-attack.xml** – XML version of MITRE™ ATT&CK™ JSON.
- **ics-attack.xml** – XML version of MITRE™ ICS ATT&CK™ JSON.
- **mobile-attack.xml** – XML version of MITRE™ Mobile ATT&CK™ JSON.

---

# 🔎 Overview

**ATT&CK™ View** is a planning tool to help defenders design adversary emulation plans using the MITRE™ ATT&CK™ framework.  
It provides a structured approach and comes bundled with a full adversary emulation plan for **APT3** (developed by MITRE™). It also serves as an example usage of teh relational data model and how to enrich teh model (extend) with additonal data such as Red Canary ATOMIC™ tests.

(Source: [MITRE Adversary Emulation Plans](https://attack.mitre.org/wiki/Adversary_Emulation_Plans))

![ATT&CK View](https://github.com/nshalabi/ATTACK-Tools/blob/master/ci/attack_view.png)

---

# 🗂 The ATT&CK™ Data Model

The ATT&CK™ framework is widely used, but many use cases require ATT&CK-enabled tools.  
This repository provides a relational database (SQLite) to simplify integration and enable building custom tools or fusing ATT&CK with other frameworks.

> Think in terms of a **data model** instead of the underlying database technology — the schema can be adapted to any DBMS.

Example conceptual model (can be implemented in any RDBMS):  
![ATT&CK Data Model](https://nosecurecode.files.wordpress.com/2022/02/61978-attackdatamodel.png)

---

# 💻 Accessing ATT&CK™ Data with SQL

Below are sample SQL queries for exploring the ATT&CK™ database.  
To run them, use any SQLite management tool (see [SQLite Management Tools](https://www.sqlite.org/cvstrac/wiki?p=ManagementTools)).

### Get the list of ATT&CK™ techniques

```sql
SELECT name
FROM sdos_object
WHERE type IS "attack-pattern";
```

**OUTPUT**

<table>
<tr><th>name</th></tr>
<tr><td>.bash_profile and .bashrc</td></tr>
<tr><td>Access Token Manipulation</td></tr>
<tr><td>Accessibility Features</td></tr>
<tr><td>Account Discovery</td></tr>
<tr><td>Account Manipulation</td></tr>
<tr><td>...</td></tr></table>

### Get techniques with their STIX 2.0 identifier

```sql
SELECT id, name
FROM sdos_object
WHERE type IS "attack-pattern";
```

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

_The_ **id** _field is a unique key that will be used frequently in many SQL queries_

The external references are stored in external_references table, since one ATT&amp;CK™ technique can have one or more references, the link between the two tables is the technique identifier (check previous query), I will list multiple ways to access the external references

### Get techniques with MITRE external IDs

```sql
SELECT name, external_id
FROM sdos_object INNER JOIN external_references
  ON sdos_object.id = external_references.fk_object_id
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

### List techniques associated with Windows platform

```sql
SELECT name, external_id
FROM sdos_object INNER JOIN external_references
  ON sdos_object.id = external_references.fk_object_id
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

### List all Malware objects

```sql
SELECT name, description
FROM sdos_object
WHERE type IS "malware";
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

### List all Adversaries (intrusion-sets)

```sql
SELECT name, description
FROM sdos_object
WHERE type IS "intrusion-set";
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

### List all Tools and Malware used by APT3

All STIX 2.0 Domain Objects (SDO) relations are stored in _"relationship"_ table. The following query is a nested query used to get the tools/malware used by APT3:

```sql
SELECT name, description
FROM sdos_object
WHERE (type IS "malware" OR type IS "tool")
  AND id IN (SELECT target_ref
             FROM relationship
             WHERE relationship_type IS "uses"
               AND source_ref IS "intrusion-set--0bbdf25b-30ff-4894-a1cd-49260d0dd2d9");
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

### Get ATOMIC™ test(s) for an ATT&CK™ technique (e.g., T1031)

ATOMIC™ Tests are stored in three tables

- atomic_test table, this table simply maps ATOMIC™ tests to ATT&CK™ techniques. Each atomic_test record has one or more atomic_attack_test records that contains the actual test details
- atomic_attack_test, this tables holds the actual ATOMIC™ test details, each test has one or more input arguments represented with an atomic_input_arguments record
- atomic_input_arguments, holds tests input arguments details

The following SQL statement retrieves the ATOMIC™ test(s) associated with ATT&CK™ technique "T1031"

```sql
SELECT name, description, executor_name, executor_command
FROM atomic_attack_test
WHERE fk_atomic_attack_id IN
  (SELECT id FROM atomic_attack
   WHERE fk_attack_external_id IS "T1031");
```

**OUTPUT**

<table>
<tr><th>name</th><th>description</th><th>executor_name</th><th>executor_command</th></tr>
<tr><td>Modify Fax service to run PowerShell</td><td>This test will temporarily modify the service Fax by changing the binPath to PowerShell<br/>and will then revert the binPath change, restoring Fax to its original state.</td><td>command_prompt</td><td>sc config Fax binPath= &quot;C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -noexit -c \&quot;write-host &#39;T1031 Test&#39;\&quot;&quot;<br/>sc start Fax<br/>sc config Fax binPath= &quot;C:\WINDOWS\system32\fxssvc.exe&quot;</td></tr></table>

---

# 📚 Additional Resources

- [MITRE ATT&CK™ : de l’importance de la temporalité](https://medium.com/cyberthreatintel/mitre-att-ck-de-limportance-de-la-temporalité-787fa81a024f)
- [Purple Team Playbook: Threat Modeling for
  Security Testingn](https://www.royalholloway.ac.uk/media/14914/techreport-mouchousf.pdf)

---

# 📬 # Support and addtional Features

For any customizations or business collaboration inquiries, please visit [applyingcode.com](http://www.applyingcode.com).
For issues or feature requests, please file a GitHub issue.  
Alternatively, email: **nader_shalabi@hotmail.com**

---

# ⚖️ License

```text
Copyright 2024 Nader Shallabi. All rights reserved.

ATT&CK™ TOOLS CAN BE COPIED AND/OR DISTRIBUTED WITHOUT ANY EXPRESS PERMISSION OF NADER SHALLABI.

THIS SOFTWARE IS PROVIDED BY NADER SHALLABI "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NADER SHALLABI
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the authors and
should not be interpreted as representing official policies, either expressed or implied, of Nader Shallabi.
```
