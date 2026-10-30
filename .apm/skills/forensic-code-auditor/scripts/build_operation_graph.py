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
TEXT_EXTS={'.sql','.plsql','.py','.java','.xml','.fmt','.js','.ts','.php','.cs','.json','.yaml','.yml','.csv','.md','.sh','.ps1','.toml'}
BINARY_CARRIERS={'.png','.jpg','.jpeg','.gif','.webp','.pdf','.mp3','.wav','.zip','.tar','.gz','.tgz','.whl'}
AGENT_CONFIG_NAMES={'.github/copilot-instructions.md','AGENTS.md','CLAUDE.md','.mcp.json','mcp.json','.vscode/mcp.json','.cursorrules'}


def build(source_root,*,evidence_root=None,exports=None,semgrep=None,manual_operations=None):
    source_root=Path(source_root).resolve();root=Path(evidence_root or source_root).resolve()
    if not source_root.is_relative_to(root):raise ValueError('source root must be under evidence root')
    exports=exports or {};operations=[];edges=[];limitations=[];files=[];categories={};sources=[];file_status={}
    reconciled={Path(p).as_posix() for p in exports.get('reconciled_files',[])}
    supplemental=list(manual_operations or [])+list(exports.get('manual_operations',[]))
    def category(name,item):categories.setdefault(name,[]).append(item)
    def add(op):
        if any(o['id']==op['id'] for o in operations):
            limitations.append('duplicate operation identifier requires qualified resolution: '+op['id']);return
        operations.append(op)
    for item in supplemental:
        if not isinstance(item,dict) or not item.get('id'):raise ValueError('manual operation requires id')
        op_path=item.get('path')
        if op_path:
            target=(source_root/op_path).resolve()
            if not target.is_relative_to(source_root) or not target.is_file():raise ValueError('manual operation path outside source root: '+str(op_path))
            ref=reference(target,root,line=item.get('line',1));reconciled.add(target.relative_to(source_root).as_posix())
        elif isinstance(item.get('source_ref'),dict):ref=item['source_ref']
        else:raise ValueError('manual operation requires path or source_ref: '+str(item['id']))
        add({'id':item['id'],'class':item.get('class','lifecycle'),'source_ref':ref,'authz_check':item.get('authz_check','unknown'),'authz_semantics':item.get('authz_semantics','NOT_VERIFIED'),'recognized_checks':list(item.get('recognized_checks',[])),'discovery_provenance':'manual_supplement'})
        if item.get('category'):category(item['category'],item['id'])
    for path in sorted(source_root.rglob('*')):
        rel_parts=path.relative_to(source_root).parts
        if any(part in SKIP for part in rel_parts):continue
        rel=path.relative_to(source_root).as_posix()
        if path.is_symlink():
            file_status[rel]='symlink_skipped';limitations.append('symlink not followed: '+rel);continue
        if not path.is_file():continue
        suffix=path.suffix.lower()
        if suffix in ('.fmb','.mmb','.pll'):
            file_status[rel]='binary_forms';limitations.append('binary Forms module requires authorized export: '+path.name);category('ui_entry',path.name);continue
        if suffix in BINARY_CARRIERS:
            files.append(reference(path,root));file_status[rel]='extracted' if rel in reconciled else 'binary_carrier'
            if rel not in reconciled:limitations.append('uninspected binary/media carrier requires metadata review: '+rel)
            continue
        is_hook=rel.startswith('.husky/') or path.name in ('Jenkinsfile','.cursorrules')
        if suffix not in TEXT_EXTS and not is_hook:
            file_status[rel]='unsupported';limitations.append('unsupported file type: '+path.name);continue
        try:text=path.read_text()
        except (OSError,UnicodeError):
            file_status[rel]='unreadable';limitations.append('unreadable source: '+path.name);continue
        files.append(reference(path,root));sources.append((path,text))
        clean=re.sub(r'/\*.*?\*/|--[^\n]*',lambda m:re.sub(r'[^\n]',' ',m.group()),text,flags=re.S)
        if suffix in ('.sql','.plsql'):
            file_status[rel]='extracted'
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
        elif suffix=='.py':
            try:tree=ast.parse(text)
            except SyntaxError:
                file_status[rel]='unreadable';limitations.append('Python parse failure: '+path.name);continue
            file_status[rel]='extracted'
            for function in ast.walk(tree):
                if not isinstance(function,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
                mutations=[node for node in ast.walk(function) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in ('save','update','delete','bulk_update','bulk_create','execute','executemany')]
                if mutations:
                    oid=str(path.relative_to(source_root))+':'+function.name
                    add({'id':oid,'class':'lifecycle','source_ref':reference(path,root,line=function.lineno),'authz_check':'unknown','authz_semantics':'NOT_VERIFIED','recognized_checks':[]})
                    if function.decorator_list:category('api_route',oid)
            limitations.append('Python reflection/imported helpers/custom mutation names require manual review: '+path.name)
        elif suffix in ('.xml','.fmt'):
            file_status[rel]='extracted'
            category('ui_entry',path.name)
            if re.search(r'(?i)menu',text):category('menu_node',path.name)
        else:
            is_ci=(rel.startswith('.github/workflows/') and suffix in ('.yml','.yaml')) or path.name in ('.gitlab-ci.yml','azure-pipelines.yml','Jenkinsfile') or rel=='.circleci/config.yml'
            is_agent=rel in AGENT_CONFIG_NAMES or rel.startswith(('.github/instructions/','.github/agents/')) or (suffix=='.json' and 'mcp' in rel.lower())
            if is_ci:
                category('batch_job',rel)
                if path.name=='copilot-setup-steps.yml':category('mcp_tool',rel)
                if rel not in reconciled:limitations.append('CI workflow/pipeline requires manual operation and trigger review: '+rel)
            elif is_agent:
                category('mcp_tool',rel)
                if rel not in reconciled:limitations.append('agent instruction or MCP configuration requires manual trust boundary review: '+rel)
            elif suffix in ('.sh','.ps1') or rel.startswith('.husky/'):
                category('batch_job',rel)
                if rel not in reconciled:limitations.append('shell or hook script requires manual operation review: '+rel)
            elif suffix=='.md':
                if rel not in reconciled:limitations.append('markdown file requires manual instruction/trust review: '+rel)
            else:
                if rel not in reconciled:limitations.append(f'no automated sink extractor for {suffix}: {path.name}')
            file_status[rel]='extracted' if rel in reconciled else 'manual_required'
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
    return {'schema_version':1,'source_digest':digest,'files':files,'file_status':file_status,'operations':sorted(operations,key=lambda o:o['id']),'edges':edges,'categories':{k:sorted(set(v)) for k,v in categories.items()},'limitations':sorted(set(limitations)),'extraction':'bounded lexical/AST candidates; no completeness claim'}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--evidence-root',type=Path);p.add_argument('--exports',type=Path);p.add_argument('--semgrep-json',type=Path);p.add_argument('--manual-operations',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:
        graph=build(a.source_root,evidence_root=a.evidence_root,exports=json.loads(a.exports.read_text()) if a.exports else None,semgrep=json.loads(a.semgrep_json.read_text()) if a.semgrep_json else None,manual_operations=json.loads(a.manual_operations.read_text()) if a.manual_operations else None)
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(graph,indent=2)+'\n')
    except (OSError,ValueError,TypeError,KeyError) as exc:p.exit(2,str(exc)+'\n')
    print(f'operations={len(graph["operations"])} edges={len(graph["edges"])} limitations={len(graph["limitations"])}')


if __name__=='__main__':main()
