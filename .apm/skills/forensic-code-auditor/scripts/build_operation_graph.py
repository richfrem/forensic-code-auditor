#!/usr/bin/env python3
"""Bounded static candidate inventory; NOT exhaustive cross-language call resolution."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

from evidence import reference

SKIP={'.git','node_modules','__pycache__','.venv','venv','.audit-work'}


def build(source_root,*,evidence_root=None,exports=None,semgrep=None):
    source_root=Path(source_root).resolve();root=Path(evidence_root or source_root).resolve()
    if not source_root.is_relative_to(root):raise ValueError('source root must be under evidence root')
    exports=exports or {};operations=[];edges=[];limitations=[];files=[];categories={};sources=[]
    def category(name,item):categories.setdefault(name,[]).append(item)
    def add(op):
        if any(o['id']==op['id'] for o in operations):
            limitations.append('duplicate operation identifier requires qualified resolution: '+op['id']);return
        operations.append(op)
    for path in sorted(source_root.rglob('*')):
        if any(part in SKIP for part in path.relative_to(source_root).parts):continue
        if path.is_symlink():limitations.append('symlink not followed: '+str(path.relative_to(source_root)));continue
        if not path.is_file():continue
        if path.suffix.lower() in ('.fmb','.mmb','.pll'):
            limitations.append('binary Forms module requires authorized export: '+path.name);category('ui_entry',path.name);continue
        if path.suffix.lower() not in ('.sql','.plsql','.py','.java','.xml','.fmt','.js','.ts','.php','.cs','.json','.yaml','.yml','.csv'):
            limitations.append('unsupported file type: '+path.name);continue
        try:text=path.read_text()
        except (OSError,UnicodeError):limitations.append('unreadable source: '+path.name);continue
        files.append(reference(path,root));sources.append((path,text))
        clean=re.sub(r'/\*.*?\*/|--[^\n]*',lambda m:re.sub(r'[^\n]',' ',m.group()),text,flags=re.S)
        if path.suffix.lower() in ('.sql','.plsql'):
            package=re.search(r'(?i)\bPACKAGE\s+BODY\s+(\w+)',clean)
            declarations=list(re.finditer(r'(?i)\b(PROCEDURE|FUNCTION)\s+([\w.]+)',clean))
            for i,match in enumerate(declarations):
                body=clean[match.end():declarations[i+1].start() if i+1<len(declarations) else len(clean)]
                if not re.search(r'(?i)\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|MERGE\s+INTO)\b',body):continue
                name=match[2].lower();name=(package[1].lower()+'.'+name) if package and '.' not in name else name
                line=text.count('\n',0,match.start())+1
                known=exports.get('authorization_functions',['assert_operation','assert_authorized','check_permission'])
                checks=[fn for fn in known if re.search(r'(?i)\b'+re.escape(fn)+r'\s*\(',body)]
                add({'id':name,'class':'lifecycle','source_ref':reference(path,root,line=line),'authz_check':'present' if checks else 'none','authz_semantics':'NOT_VERIFIED','recognized_checks':checks})
                category('stored_procedure',name)
            if declarations:limitations.append('SQL subprogram boundaries/calls are lexical candidates; nested/overloaded bodies need manual review: '+path.name)
            for label,pattern in [('db_grant',r'(?i)\bGRANT\s+'),('scheduler',r'(?i)\bDBMS_SCHEDULER\.'),('direct_db_access',r'(?i)\bGRANT\s+(?:UPDATE|INSERT|DELETE)\b'),('db_link',r'(?i)\bCREATE\s+DATABASE\s+LINK\b')]:
                if re.search(pattern,clean):category(label,path.name)
            for match in re.finditer(r'(?i)\b(?:EXECUTE\s+IMMEDIATE|CREATE\s+(?:OR\s+REPLACE\s+)?SYNONYM)\b',clean):
                line=text.count('\n',0,match.start())+1
                edges.append({'from':f'{path.relative_to(root)}:{line}','to':'dynamic-or-synonym-target','kind':'unresolved_dispatch','status':'unresolved','evidence_ref':reference(path,root,line=line)})
                limitations.append('dynamic SQL/synonym target unresolved: '+path.name)
        elif path.suffix=='.py':
            try:tree=ast.parse(text)
            except SyntaxError:limitations.append('Python parse failure: '+path.name);continue
            for function in ast.walk(tree):
                if not isinstance(function,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
                mutations=[node for node in ast.walk(function) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in ('save','update','delete','bulk_update','bulk_create','execute','executemany')]
                if mutations:
                    oid=str(path.relative_to(source_root))+':'+function.name
                    add({'id':oid,'class':'lifecycle','source_ref':reference(path,root,line=function.lineno),'authz_check':'unknown','authz_semantics':'NOT_VERIFIED','recognized_checks':[]})
                    if function.decorator_list:category('api_route',oid)
            limitations.append('Python reflection/imported helpers/custom mutation names require manual review: '+path.name)
        elif path.suffix in ('.xml','.fmt'):
            category('ui_entry',path.name)
            if re.search(r'(?i)menu',text):category('menu_node',path.name)
    known={o['id'] for o in operations}
    for path,text in sources:
        for match in re.finditer(r'(?i)\b([a-z_]\w*\.[a-z_]\w*)\s*\(',text):
            target=match[1].lower();kind=None
            if path.suffix in ('.xml','.fmt'):kind='forms_call'
            elif path.suffix=='.java' and re.search(r'(?i)(prepareCall|\{\s*call)',text):kind='jdbc_call';category('api_route',path.name)
            elif path.suffix in ('.js','.ts','.py') and target in known:kind='api_call';category('api_route',path.name)
            if kind is None:continue
            line=text.count('\n',0,match.start())+1
            edges.append({'from':f'{path.relative_to(root)}:{line}','to':target,'kind':kind,'status':'established' if target in known else 'unresolved','evidence_ref':reference(path,root,line=line),'connection_identity':exports.get('connections',{}).get(path.name,'unknown'),'identity_provenance':'declared-export' if path.name in exports.get('connections',{}) else 'unknown'})
            if target not in known:limitations.append('caller target unavailable: '+target)
    for hit in (semgrep or {}).get('results',[]):
        path=Path(hit['path']);path=path if path.is_absolute() else source_root/path
        if not path.resolve().is_relative_to(source_root) or not path.is_file():raise ValueError('Semgrep location outside source snapshot')
        label=hit.get('extra',{}).get('metadata',{}).get('category','unknown')
        if label!='unknown':category(label,str(path.relative_to(source_root)))
    for error in (semgrep or {}).get('errors',[]):limitations.append('Semgrep extraction error: '+str(error.get('type','unknown')))
    digest=hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()
    return {'schema_version':1,'source_digest':digest,'files':files,'operations':sorted(operations,key=lambda o:o['id']),'edges':edges,'categories':{k:sorted(set(v)) for k,v in categories.items()},'limitations':sorted(set(limitations)),'extraction':'bounded lexical/AST candidates; no completeness claim'}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--evidence-root',type=Path);p.add_argument('--exports',type=Path);p.add_argument('--semgrep-json',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:
        graph=build(a.source_root,evidence_root=a.evidence_root,exports=json.loads(a.exports.read_text()) if a.exports else None,semgrep=json.loads(a.semgrep_json.read_text()) if a.semgrep_json else None)
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(graph,indent=2)+'\n')
    except (OSError,ValueError,TypeError,KeyError) as exc:p.exit(2,str(exc)+'\n')
    print(f'operations={len(graph["operations"])} edges={len(graph["edges"])} limitations={len(graph["limitations"])}')


if __name__=='__main__':main()
