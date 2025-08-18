<?php

interface IGlobal extends ArrayAccess, IteratorAggregate, Countable
{
    public function all(): array;
    public function clear(): void;
}

interface ISession extends IGlobal {}
class Session implements ISession
{
    public function offsetExists(mixed $offset): bool {
        return isset($_SESSION[$offset]);
    }

    public function offsetGet(mixed $offset): mixed {
        return $_SESSION[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void {
        $_SESSION[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void {
        unset($_SESSION[$offset]);
    }

    public function getIterator(): Traversable {
        return new ArrayIterator($_SESSION);
    }

    public function count(): int {
        return count($_SESSION);
    }

    public function all(): array {
        return $_SESSION;
    }

    public function clear(): void {
        $_SESSION = [];
    }
}

interface IGet extends IGlobal {}
class Get implements IGet
{
    public function offsetExists(mixed $offset): bool {
        return isset($_GET[$offset]);
    }

    public function offsetGet(mixed $offset): mixed {
        return $_GET[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void {
        $_GET[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void {
        unset($_GET[$offset]);
    }

    public function getIterator(): Traversable {
        return new ArrayIterator($_GET);
    }

    public function count(): int {
        return count($_GET);
    }

    public function all(): array {
        return $_GET;
    }

    public function clear(): void {
        $_GET = [];
    }
}

interface IPost extends IGlobal {}
class Post implements IPost
{
    public function offsetExists(mixed $offset): bool {
        return isset($_POST[$offset]);
    }

    public function offsetGet(mixed $offset): mixed {
        return $_POST[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void {
        $_POST[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void {
        unset($_POST[$offset]);
    }

    public function getIterator(): Traversable {
        return new ArrayIterator($_POST);
    }

    public function count(): int {
        return count($_POST);
    }

    public function all(): array {
        return $_POST;
    }

    public function clear(): void {
        $_POST = [];
    }
}

interface IServer extends IGlobal {}
class Server implements IServer
{
    public function offsetExists(mixed $offset): bool {
        return isset($_SERVER[$offset]);
    }

    public function offsetGet(mixed $offset): mixed {
        return $_SERVER[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void {
        $_SERVER[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void {
        unset($_SERVER[$offset]);
    }

    public function getIterator(): Traversable {
        return new ArrayIterator($_SERVER);
    }

    public function count(): int {
        return count($_SERVER);
    }

    public function all(): array {
        return $_SERVER;
    }

    public function clear(): void {
        $_SERVER = [];
    }
}

interface IEnv extends IGlobal {}
class Env implements IEnv
{
    public function offsetExists(mixed $offset): bool {
        return isset($_ENV[$offset]);
    }

    public function offsetGet(mixed $offset): mixed {
        return $_ENV[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void {
        $_ENV[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void {
        unset($_ENV[$offset]);
    }

    public function getIterator(): Traversable {
        return new ArrayIterator($_ENV);
    }

    public function count(): int {
        return count($_ENV);
    }

    public function all(): array {
        return $_ENV;
    }

    public function clear(): void {
        $_ENV = [];
    }
}

interface IFiles extends IGlobal {}
class Files implements IFiles
{
    public function offsetExists(mixed $offset): bool {
        return isset($_FILES[$offset]);
    }

    public function offsetGet(mixed $offset): mixed {
        return $_FILES[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void {
        $_FILES[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void {
        unset($_FILES[$offset]);
    }

    public function getIterator(): Traversable {
        return new ArrayIterator($_FILES);
    }

    public function count(): int {
        return count($_FILES);
    }

    public function all(): array {
        return $_FILES;
    }

    public function clear(): void {
        $_FILES = [];
    }
}


