# v2.7.1 — Fix de compilación de túneles

Corrige el build de la v2.7.0 después de añadir `AbrirWeb` al modelo de túneles. Los cinco túneles predeterminados todavía se inicializaban con literales posicionales de tres campos, por lo que Go devolvía `too few values in struct literal`.

Ahora se usan campos nombrados, por ejemplo:

```go
{Puerto: 8888, Nombre: "Panel"}
```

Esto corrige el build y hace esos valores más resistentes a futuros cambios en el struct `Tunel`. También se actualizó la metadata de Windows a 2.7.1.
