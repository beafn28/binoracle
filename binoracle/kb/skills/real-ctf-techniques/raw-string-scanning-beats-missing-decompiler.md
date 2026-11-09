# Técnica: escaneo crudo de strings/constantes cuando falta un decompilador para el formato

## Patrón a reconocer

El binario es de un formato/arquitectura para el que no hay (o no está instalado) un
decompilador completo: .NET/CIL sin ilspycmd/monodis, Z80 (calculadoras TI) sin un
desensamblador dedicado, u otra ISA exótica. La tentación es reportar "no se puede analizar sin
la herramienta X" -- pero muchas veces el DATO que se busca (una constante, un string cifrado,
una tabla) vive en una sección de datos simple (metadatos, `.rodata`, un heap de strings) que
SÍ es legible con un escaneo de bytes genérico, sin necesitar entender el bytecode/ISA en sí.

## Por qué importa

Un string o blob de datos constante casi nunca depende de la ISA del código que lo usa -- vive
como bytes planos (ASCII, UTF-16LE, una tabla de enteros) en una sección de datos, sin importar
si el CÓDIGO que lo referencia es x86, CIL de .NET, o Z80. La utilidad de escaneo de strings de
binoracle (`iocscan._iter_strings`, o el heap de metadatos `.NET` `#US` que ya lee
`dotnetinspect.py`) suele ser suficiente para extraer el dato sin ningún decompilador.

## Cómo aplicarlo

1. Antes de concluir "necesito la herramienta X para este formato", prueba primero las
   utilidades de extracción de strings/constantes genéricas de binoracle contra el archivo
   crudo (`binoracle secrets`, `r2_strings`, o el parser de metadatos específico del formato si
   existe, p.ej. `binoracle dotnet`).
2. Busca el dato (string cifrada, tabla de permutación, constante mágica) directamente en los
   bytes, sin pasar por el bytecode: muchas veces aparece literal o con una codificación simple
   (Base32, Morse, UTF-16LE) reconocible a simple vista.
3. Si el formato tiene un heap de datos dedicado (como el heap `#US` de ECMA-335 para strings
   .NET, que almacena los literales que `ldstr` referencia -- distinto del heap `#Strings` de
   NOMBRES de tipos/métodos), asegúrate de que la utilidad de binoracle lee ESE heap concreto,
   no solo el de nombres.
4. Cuando el dato SÍ requiere analizar lógica/algoritmo específico de la ISA (no solo extraer
   una constante), ahí sí es necesario un desensamblador/plugin para esa arquitectura concreta
   (p.ej. el plugin Z80 de r2) -- pero muchos retos solo necesitan el paso 1-3 para llegar a la
   flag.

## Casos reales confirmados esta sesión

- `Dotty` (RaRCTF 2021, .NET/CIL): el string codificado (Morse + Base32 anidados) vivía como
  constante estática en los metadatos del ensamblado. Se localizó con la utilidad de extracción
  de strings de binoracle (sin decompilador .NET), se decodificó con Morse y Base32 estándar, y
  coincidió exacto contra el writeup -- de paso se confirmó y arregló que `dotnetinspect.py`
  nunca leía el heap `#US` (solo `#Strings`), un gap real ya corregido esa misma sesión.
- `Not-So-E(Z80)` (Buckeye 2021, TI-83+ .8xp): aunque el ALGORITMO sí necesitó el desensamblador
  Z80 de r2 para entender el bucle de descifrado, confirmar la clave exacta se hizo buscando el
  texto cifrado esperado directamente en los bytes crudos del `.8xp` con la clave corregida --
  confirmando (y corrigiendo un error del propio writeup original) sin ejecutar nada.
