import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Home from './pages/Home';
import Scanning from './pages/Scanning';
import Results from './pages/Results';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/scanning/:jobId" element={<Scanning />} />
        <Route path="/results/:jobId" element={<Results />} />
      </Routes>
    </BrowserRouter>
  );
}
