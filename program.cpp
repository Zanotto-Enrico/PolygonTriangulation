#include "headers.hpp"
#include <regex>

std::vector<Triangle> getMesh(std::vector<Coord> polygon)
{
  double height = 10;

  std::vector<Triangle> triangles;


    for (auto p : partitionPolygonIntoMonotone(polygon))
    {
      for(auto t : triangulateMonotonePolygon(p) )
      {
        triangles.push_back(t);
      }
    }

    return triangles;
}


void getUserInput(std::vector<Coord> &polygon)
{

  std::cout << "Insert the number of vertices: ";
  int numVertices;
  std::cin >> numVertices;

  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 

  std::cout << "Insert a line for each vertex with the format: (x;y)\n";

  std::regex pattern(R"(\((-?\d+(\.\d+)?);(-?\d+(\.\d+)?)\))");

  for (int i = 0; i < numVertices; ++i) {
      std::string input;
      std::cout << "Vertex " << i+1 << ": ";
      std::getline(std::cin, input);

      std::smatch match;
      if (std::regex_match(input, match, pattern)) {
          Coord vertex;
          vertex.x = std::stod(match[1]);
          vertex.y = std::stod(match[3]);
          polygon.push_back(vertex);
      } else {
          std::cout << "Invalid input format. Please use the format (x;y)\n";
          --i; // Repeat the current vertex input
      }
  }
}


int main(int argc, char* argv[])
{
  while(1){
    std::vector<Coord> polygon;

    getUserInput(polygon);

    std::vector<Triangle> triangles = getMesh(polygon);

    for (Triangle triangle : triangles)
    {
      std::cout << "[(" <<  triangle.p1.x << ";" << triangle.p1.y  << 
                  "),(" <<  triangle.p2.x << ";" << triangle.p2.y  <<
                  "),(" <<  triangle.p3.x << ";" << triangle.p3.y  << ")]"<<std::endl;
    }
    std::cout << "end\n";
  }
  return 0;
}