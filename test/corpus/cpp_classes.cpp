// Classes, virtual dispatch, exceptions (flatten must leave EH functions alone), std::string and
// std::vector. Exercises the paths that invoke/landingpad terminators guard in the flattener.
#include <cstdio>
#include <string>
#include <vector>
#include <stdexcept>
#include <numeric>

struct Shape {
    virtual ~Shape() = default;
    virtual long area() const = 0;
    virtual std::string name() const = 0;
};
struct Square : Shape {
    long s;
    explicit Square(long s) : s(s) {}
    long area() const override { return s * s; }
    std::string name() const override { return "shape::square"; }
};
struct Rect : Shape {
    long w, h;
    Rect(long w, long h) : w(w), h(h) {}
    long area() const override { return w * h; }
    std::string name() const override { return "shape::rect"; }
};

static long checked_div(long a, long b) {
    if (b == 0) throw std::runtime_error("division::by::zero");
    return a / b;
}

int main() {
    std::vector<Shape *> shapes;
    shapes.push_back(new Square(5));
    shapes.push_back(new Rect(3, 7));
    shapes.push_back(new Square(9));

    long total = 0;
    std::string last;
    for (auto *s : shapes) { total += s->area(); last = s->name(); }

    long caught = 0;
    try { checked_div(100, 0); } catch (const std::exception &e) { caught = (long)std::string(e.what()).size(); }

    std::vector<long> v(10);
    std::iota(v.begin(), v.end(), 1);
    long sum = std::accumulate(v.begin(), v.end(), 0L);

    std::printf("total=%ld last=%s caught=%ld sum=%ld\n", total, last.c_str(), caught, sum);
    for (auto *s : shapes) delete s;
    return 0;
}
