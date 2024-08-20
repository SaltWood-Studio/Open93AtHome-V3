import { Table } from "../sqlite";

// TypeScript 等效的 UserEntity 类
@Table('users', `
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT NOT NULL, 
    photo TEXT
`)
export class UserEntity {
    public id: number;
    public username: string;
    public photo: string;

    constructor(id: number = 0, username: string = '', photo: string = '') {
        this.id = id;
        this.username = username;
        this.photo = photo;
    }
}