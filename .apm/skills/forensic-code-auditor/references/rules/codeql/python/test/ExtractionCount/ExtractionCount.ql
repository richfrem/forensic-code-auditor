import python
select count(File f | f.getRelativePath().matches("%views.py"))
