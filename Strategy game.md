
'''
https://stackoverflow.com/questions/29414171/whats-the-rust-way-to-modify-a-structure-within-nested-loops

I know the question is like 2 years old, but I got curious about it.

This C# program produces the original desired output:

```rust
var bodies = new[] { new Body { X = 10, Y = 10, V = 0 },
                     new Body { X = 20, Y = 30, V = 0 } };

for (int i = 0; i < 2; i++)
{
    Console.WriteLine("Turn {0}", i);

    foreach (var bOuter in bodies)
    {
        Console.WriteLine("x:{0}, y:{1}, v:{2}", bOuter.X, bOuter.Y, bOuter.V);
        var a = bOuter.V;
        foreach (var bInner in bodies)
        {
            a = a + bOuter.X * bInner.X;
            Console.WriteLine("    x:{0}, y:{1}, v:{2}, a:{3}", bInner.X, bInner.Y, bInner.V, a);
        }
        bOuter.V = a;
    }
}
```

Since only `v` is ever changed, we _could_ change the struct to something like this:

```rust
struct Body {
    x: i16,
    y: i16,
    v: Cell<i16>,
}
```

Now I'm able to mutate `v`, and the program becomes:

```rust
// keep it simple and loop only twice
for i in 0..2 {
    println!("Turn {}", i);
    for b_outer in bodies.iter() {

        let mut a = b_outer.v.get();

        println!("x:{}, y:{}, v:{}", b_outer.x, b_outer.y, a);
        for b_inner in bodies.iter() {

            a = a + (b_outer.x * b_inner.x);

            println!(
                "    x:{}, y:{}, v:{}, a:{}",
                b_inner.x,
                b_inner.y,
                b_inner.v.get(),
                a
            );
        }

        b_outer.v.set(a);
    }
}
```

It produces the same output as the C# program above. The "downside" is that whenever you want to work with `v`, you need use `get()` or `into_inner()`. There may be other downsides I'm not aware of.
'''

Melee animations:

1)  Engaged - shield to shield, either trying to stab around or trying to protect self
2)  Assisting the engaged unit, trying to stab around from behind
3)  Sprint and push - units in the back might push with shields too (maybe push is toggleable, foxus either on push or on kill)


Attack 
Block
Dodge

![[Drawing 2023-03-05 03.54.50.excalidraw]]