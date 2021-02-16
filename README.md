# bloodhound-quickwin
Simple script to extract useful informations from the combo BloodHound + Neo4j. Can help to define a target.

## Prerequisites
- python3
```bash
pip3 install py2neo
pip3 install pandas
```
## Example
- Use your favorite [ingestor](https://github.com/fox-it/BloodHound.py) to gather ".json"
- Start your neo4j console
- Import "*.json" in [bloodhounnd](https://github.com/fox-it/BloodHound.py)
- Run ./bhqc.py
