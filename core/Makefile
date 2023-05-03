ODIR = obj
RDIR = bin/Release
DDIR = bin/Debug

debug : $(ODIR)/main.o $(ODIR)/attack_graph.o $(ODIR)/rule_functions.o $(ODIR)/tag.o $(ODIR)/log.o
	g++ -I/usr/include/cppconn -o bin/Debug/dag.exe $(ODIR)/main.o $(ODIR)/attack_graph.o $(ODIR)/rule_functions.o $(ODIR)/tag.o $(ODIR)/log.o -L/usr/lib/ -lboost_date_time -lmysqlcppconn -pthread 

release : $(ODIR)/main.o $(ODIR)/attack_graph.o $(ODIR)/rule_functions.o $(ODIR)/tag.o $(ODIR)/log.o
	g++ -O2 -I/usr/include/cppconn -o bin/Release/dag.exe $(ODIR)/main.o $(ODIR)/attack_graph.o $(ODIR)/rule_functions.o $(ODIR)/tag.o $(ODIR)/log.o -L/usr/lib/ -lboost_date_time -lmysqlcppconn -pthread

$(ODIR)/main.o : main.cpp
	g++ -c -Wall main.cpp -o $(ODIR)/main.o

$(ODIR)/attack_graph.o : attack_graph.cpp
	g++ -c -Wall attack_graph.cpp -o $(ODIR)/attack_graph.o

$(ODIR)/rule_functions.o : rule_functions.cpp
	g++ -c -Wall rule_functions.cpp -o $(ODIR)/rule_functions.o

$(ODIR)/tag.o : tag.cpp
	g++ -c -Wall tag.cpp -o $(ODIR)/tag.o
	
$(ODIR)/log.o : log.cpp
	g++ -c -Wall log.cpp -o $(ODIR)/log.o

clean: 
	rm -f obj/*.o

clean_all:
	rm -f obj/*.o bin/*/*.exe
