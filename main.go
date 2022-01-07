package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/neo4j/neo4j-go-driver/neo4j"
)

var dbSession neo4j.Session

type data struct {
	Dprts []dpt `json:"departments"`
}

type dpt struct {
	Name  string `json:"name"`
	Teams []team `json:"teams"`
}

type team struct {
	Name     string `json:"name"`
	Services []srv  `json:"services"`
}

type srv struct {
	Name string   `json:"name"`
	IPS  []string `json:"ips"`
}

func init() {
	dbUri := "neo4j://localhost:7687"
	dbDriver, err := neo4j.NewDriver(dbUri, neo4j.BasicAuth("neo4j", "test", ""), func(c *neo4j.Config) {
		c.Encrypted = false
	})
	if err != nil {
		panic(err)
	}
	dbSession, err = dbDriver.NewSession(neo4j.SessionConfig{})
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	org := flag.String("policy", "", "org_policy")
	report := flag.String("report", "", "Flan report")
	flag.Parse()

	if *org == "" || *report == "" {
		flag.Usage()
		os.Exit(1)
	}
	b, err := ioutil.ReadFile(*org)
	if err != nil {
		log.Fatal(err)
	}

	d := data{}
	if err := json.Unmarshal(b, &d); err != nil {
		log.Fatal(err)
	}
	if err := persistFile(dbSession, d); err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadFile(*report)
	if err != nil {
		log.Fatal(err)
	}

	f := flanReport{}
	if err := json.Unmarshal(body, &f); err != nil {
		log.Fatal(err)
	}

	for process, novl := range f.NotVulnerable {
		for ip, ports := range novl.Location {
			if err := addProcessNode(dbSession, process, ip); err != nil {
				log.Fatal(err)
			}
			for _, port := range ports {
				if err = addPortNode(dbSession, port, ip); err != nil {
					log.Fatal(err)
				}
			}
		}
	}

	for process, vl := range f.ListVulns {
		for ip, ports := range vl.Location {
			if err := addProcessNode(dbSession, process, ip); err != nil {
				log.Fatal(err)
			}
			for _, port := range ports {
				if err = addPortNode(dbSession, port, ip); err != nil {
					log.Fatal(err)
				}
			}
			for _, vln := range vl.V {
				if err = addVlnNode(dbSession, vln.Name, ip, vln.Type, vln.SeverityStr, vln.Severity); err != nil {
					log.Fatal(err)
				}
			}
		}
	}

	if err = portRelationship(dbSession); err != nil {
		log.Fatal(err)
	}

	if err := processRelationship(dbSession); err != nil {
		log.Fatal(err)
	}

	if err = vulnRelationship(dbSession); err != nil {
		log.Fatal(err)
	}
}
func vulnRelationship(dbSession neo4j.Session) error {
	result, _ := dbSession.Run(`match (v:vulnerability), (p:process) where p.ip = v.ip CREATE (p)-[r:VULNERABILITY]->(v)`, map[string]interface{}{})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func portRelationship(dbSession neo4j.Session) error {
	result, _ := dbSession.Run(`match (prt:port), (i:ip) where prt.ip = i.ip CREATE (i)-[r:HAS]->(prt)`, map[string]interface{}{})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func processRelationship(dbSession neo4j.Session) error {
	result, _ := dbSession.Run(`match (prt:port), (p:process) where prt.ip = p.ip CREATE (p)-[r:RUNS]->(prt)`, map[string]interface{}{})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func addVlnNode(dbSession neo4j.Session, name, ip, typ, severity_str string, severity float64) error {
	result, _ := dbSession.Run(`CREATE (v:vulnerability{name:$data, ip:$ip, type:$type, severity:$severity, severity_str:$severity_str})
	`, map[string]interface{}{
		"data":         name,
		"ip":           ip,
		"type":         typ,
		"severity":     fmt.Sprintf("%f", severity),
		"severity_str": severity_str,
	})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func addProcessNode(dbSession neo4j.Session, name, ip string) error {
	result, _ := dbSession.Run(`CREATE (p:process{name:$data, ip:$ip})
	`, map[string]interface{}{
		"data": name,
		"ip":   ip,
	})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func addPortNode(dbSession neo4j.Session, port int, ip string) error {
	result, _ := dbSession.Run(`CREATE (prt:port{number:$data, ip:$ip})
	`, map[string]interface{}{
		"data": strconv.Itoa(port),
		"ip":   ip,
	})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func addTeamNode(dbSession neo4j.Session, t string) error {
	result, _ := dbSession.Run(`CREATE (t:team{name:$data})
	`, map[string]interface{}{
		"data": t,
	})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func addServiceNode(dbSession neo4j.Session, service string) error {
	result, _ := dbSession.Run(`CREATE (s:service{name:$data})
	`, map[string]interface{}{
		"data": service,
	})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func addIPNode(dbSession neo4j.Session, ip string) error {
	result, _ := dbSession.Run(`CREATE (i:ip{ip:$data})
	`, map[string]interface{}{
		"data": ip,
	})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func addDepartments(dbSession neo4j.Session, dprt string) error {
	result, _ := dbSession.Run(`CREATE (d:depart{name:$data})`, map[string]interface{}{
		"data": dprt,
	})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func runsRelationship(dbSession neo4j.Session, srv, ip string) error {
	result, _ := dbSession.Run(`
	MATCH
	(i:ip),
	(s:service)
	WHERE i.ip= $ip AND s.name=$name
	CREATE (s)-[r:RUNS_ON]->(i)`, map[string]interface{}{
		"ip":   ip,
		"name": srv,
	})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func teamRelationship(dbSession neo4j.Session, team, service string) error {
	result, _ := dbSession.Run(`MATCH
	(t:team),
	(s:service)
	WHERE t.name = $teamName AND s.name = $service
	CREATE (t)-[r:HAS]->(s)`, map[string]interface{}{
		"teamName": team,
		"service":  service,
	})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func DprtRelationship(dbSession neo4j.Session, dprt, team string) error {
	result, _ := dbSession.Run(`MATCH
	(d:depart),
	(t:team)
	WHERE d.name = $dptName AND t.name = $teamName
	CREATE (d)-[r:HAS]->(t)`, map[string]interface{}{
		"dptName":  dprt,
		"teamName": team,
	})
	if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func persistFile(dbSession neo4j.Session, d data) error {
	for _, dprt := range d.Dprts {
		for _, team := range dprt.Teams {
			if err := addDepartments(dbSession, dprt.Name); err != nil {
				return fmt.Errorf("failed to add department node error: %v", err)
			}
			if err := addTeamNode(dbSession, team.Name); err != nil {
				return fmt.Errorf("failed to add team node error: %v", err)
			}
			if err := DprtRelationship(dbSession, dprt.Name, team.Name); err != nil {
				return fmt.Errorf("failed to create relationship error: %v", err)
			}
			for _, srvc := range team.Services {
				if err := addServiceNode(dbSession, srvc.Name); err != nil {
					return fmt.Errorf("failed to add service node error: %v", err)
				}
				for _, ip := range srvc.IPS {
					if err := addIPNode(dbSession, ip); err != nil {
						return fmt.Errorf("failed to add IP node error: %v", err)
					}
					if err := runsRelationship(dbSession, srvc.Name, ip); err != nil {
						return fmt.Errorf("failed to create relationship error: %v", err)
					}
				}
				if err := teamRelationship(dbSession, team.Name, srvc.Name); err != nil {
					return fmt.Errorf("failed to create relationship error: %v", err)
				}
			}
		}
	}
	return nil
}
