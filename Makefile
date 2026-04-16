CXX = clang++
CXXFLAGS = -Wall -Wextra -std=c++17 -I/opt/homebrew/opt/libsodium/include
LDFLAGS = -L/opt/homebrew/opt/libsodium/lib -lsodium
SRCS = main.cpp

muninn: $(SRCS)
	$(CXX) $(CXXFLAGS) -o muninn $(SRCS) $(LDFLAGS)

clean:
	rm -f muninn